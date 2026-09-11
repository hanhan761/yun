#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import secrets
import shutil
import shlex
import subprocess
import sys
import tempfile
from typing import Any, Sequence


SKILL_ROOT = pathlib.Path(__file__).resolve().parents[1]
RUNNER_PATH = pathlib.Path(__file__).with_name("yun_job_runner.sh")
DEFAULT_REGISTRY_PATH = pathlib.Path.home() / ".config" / "yun" / "targets.json"
REGISTRY_ENV = "YUN_TARGETS_FILE"
JOB_ROOT = ".yun/jobs"
JOB_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
TARGET_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$|^[a-z0-9]$")
HOST_FINGERPRINT_PATTERN = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
HOST_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
SSH_USER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
WINDOWS_USER_PATTERN = re.compile(r"^(?:[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\\)?[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")
BUNDLE_PREFIX = b"# YUN-BUNDLE-V1 "
BUNDLE_SCHEMA_VERSION = 1
BUNDLE_MAX_HEADER_BYTES = 8192
MAX_PRIVATE_KEY_BYTES = 1024 * 1024
BUNDLE_KEYS = {
    "schema_version",
    "name",
    "connection",
    "known_hosts_line",
    "host_key_sha256",
    "client_key_sha256",
}
BUNDLE_CONNECTION_KEYS = {
    "description",
    "hostname",
    "port",
    "user",
    "roles",
    "protected",
}
ALLOWED_ROLES = {"server", "compute"}
ALLOWED_TARGET_KEYS = {
    "platform",
    "description",
    "hostname",
    "port",
    "user",
    "identity_file",
    "known_hosts_file",
    "expected_host_key_sha256",
    "roles",
    "protected",
    "compute_backend",
    "job_root",
}


class YunError(RuntimeError):
    pass


def printable(argv: Sequence[str]) -> str:
    return shlex.join([str(item) for item in argv])


def run_external(
    argv: Sequence[str],
    *,
    capture: bool = False,
    dry_run: bool = False,
    display: str | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    print(f"+ {display or printable(argv)}", file=sys.stderr)
    if dry_run:
        return subprocess.CompletedProcess(list(argv), 0, "", "")
    try:
        return subprocess.run(
            [str(item) for item in argv],
            check=False,
            capture_output=capture,
            text=True,
            encoding="utf-8",
            errors="replace",
            input=input_text,
        )
    except FileNotFoundError as exc:
        raise YunError(f"required command is missing: {argv[0]}") from exc


def registry_path() -> pathlib.Path:
    configured = os.environ.get(REGISTRY_ENV)
    path = pathlib.Path(configured) if configured else DEFAULT_REGISTRY_PATH
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(SKILL_ROOT)
    except ValueError:
        return resolved
    raise YunError("registry must remain outside the installed skill directory")


def empty_registry() -> dict[str, Any]:
    return {"schema_version": 1, "targets": {}}


def validate_target_name(name: str) -> str:
    if not TARGET_NAME_PATTERN.fullmatch(name):
        raise YunError("target name must use 1-64 lowercase letters, digits, or hyphens")
    return name


def validate_hostname(value: str) -> str:
    if not value or len(value) > 253 or any(ord(character) < 33 for character in value):
        raise YunError("hostname must be a DNS name or IP address without whitespace")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        dns_name = value[:-1] if value.endswith(".") else value
        labels = dns_name.split(".")
        if not labels or any(not HOST_LABEL_PATTERN.fullmatch(label) for label in labels):
            raise YunError("hostname must be a DNS name or IP address")
        return value


def validate_target(name: str, target: Any) -> dict[str, Any]:
    validate_target_name(name)
    if not isinstance(target, dict):
        raise YunError(f"target {name!r} must be an object")
    unknown = set(target) - ALLOWED_TARGET_KEYS
    if unknown:
        raise YunError(f"target {name!r} has unknown fields: {', '.join(sorted(unknown))}")

    required_strings = (
        "description",
        "hostname",
        "user",
        "identity_file",
        "known_hosts_file",
        "expected_host_key_sha256",
    )
    for field in required_strings:
        value = target.get(field)
        if not isinstance(value, str) or not value.strip():
            raise YunError(f"target {name!r} requires nonempty {field}")
    description = str(target["description"])
    if len(description) > 200 or any(character in description for character in "\r\n\x00"):
        raise YunError(f"target {name!r} has invalid description")
    try:
        validate_hostname(str(target["hostname"]))
    except YunError as exc:
        raise YunError(f"target {name!r} has invalid hostname: {exc}") from exc
    platform = target.get("platform", "linux")
    if platform not in ("linux", "windows"):
        raise YunError(f"target {name!r} has invalid platform")
    user_pattern = WINDOWS_USER_PATTERN if platform == "windows" else SSH_USER_PATTERN
    if not user_pattern.fullmatch(str(target["user"])):
        raise YunError(f"target {name!r} has invalid user")
    port = target.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise YunError(f"target {name!r} has invalid port")
    identity_value = str(target["identity_file"])
    known_hosts_value = str(target["known_hosts_file"])
    if any(ord(character) < 32 for character in identity_value + known_hosts_value):
        raise YunError(f"target {name!r} has a control character in a local path")
    identity_file = pathlib.Path(identity_value).expanduser()
    known_hosts_file = pathlib.Path(known_hosts_value).expanduser()
    if not identity_file.is_absolute() or identity_file.suffix.lower() != ".pem":
        raise YunError(f"target {name!r} identity_file must be an absolute .pem path")
    if not known_hosts_file.is_absolute():
        raise YunError(f"target {name!r} known_hosts_file must be an absolute path")
    if not HOST_FINGERPRINT_PATTERN.fullmatch(str(target["expected_host_key_sha256"])):
        raise YunError(f"target {name!r} has invalid SHA-256 host fingerprint")
    if not isinstance(target.get("protected"), bool):
        raise YunError(f"target {name!r} requires boolean protected")

    roles = target.get("roles")
    if (
        not isinstance(roles, list)
        or not roles
        or any(not isinstance(role, str) or role not in ALLOWED_ROLES for role in roles)
        or len(set(roles)) != len(roles)
    ):
        raise YunError(f"target {name!r} has invalid roles")
    if "compute" in roles:
        if platform == "windows":
            raise YunError("Windows targets support server operations only; compute requires Linux tmux")
        if target.get("compute_backend") != "tmux" or target.get("job_root") != JOB_ROOT:
            raise YunError(f"target {name!r} compute contract must use tmux and {JOB_ROOT}")
    elif target.get("compute_backend") is not None or target.get("job_root") is not None:
        raise YunError(f"target {name!r} has compute fields without the compute role")
    return target


def validate_registry(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "targets"}:
        raise YunError("registry must contain only schema_version and targets")
    if payload.get("schema_version") != 1 or not isinstance(payload.get("targets"), dict):
        raise YunError("invalid targets registry schema")
    identity_owners: dict[str, str] = {}
    for name, target in payload["targets"].items():
        validate_target(name, target)
        identity_path = pathlib.Path(str(target["identity_file"])).expanduser().resolve()
        identity_key = os.path.normcase(str(identity_path))
        existing_owner = identity_owners.get(identity_key)
        if existing_owner is not None:
            raise YunError(
                f"targets {existing_owner!r} and {name!r} cannot share one PEM identity"
            )
        identity_owners[identity_key] = name
    return payload


def load_registry_payload() -> dict[str, Any]:
    path = registry_path()
    if not path.is_file():
        raise YunError(f"registry is missing: {path}; run 'python scripts/yunctl.py init'")
    return validate_registry(json.loads(path.read_text(encoding="utf-8")))


def load_registry_or_empty() -> dict[str, Any]:
    return load_registry_payload() if registry_path().is_file() else empty_registry()


def load_registry() -> dict[str, dict[str, Any]]:
    return load_registry_payload()["targets"]


def restrict_local_file(path: pathlib.Path) -> None:
    if os.name == "nt":
        username = os.environ.get("USERNAME")
        if not username:
            raise YunError("USERNAME is unavailable for Windows ACL restriction")
        result = run_external(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{username}:(F)"]
        )
        if result.returncode != 0:
            raise YunError(f"failed to restrict ACL: {path}")
    else:
        path.chmod(0o600)


def write_registry(payload: dict[str, Any], *, dry_run: bool = False) -> None:
    validate_registry(payload)
    path = registry_path()
    if dry_run:
        print(f"would_write_registry={path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    handle, temporary_name = tempfile.mkstemp(prefix=".targets-", suffix=".json", dir=path.parent)
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            temporary.chmod(0o600)
        os.replace(temporary, path)
        restrict_local_file(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_public_text(path: pathlib.Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            temporary.chmod(0o644)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def get_target(name: str) -> dict[str, Any]:
    target = load_registry().get(name)
    if target is None:
        raise YunError(f"unregistered target: {name}")
    return validate_target(name, target)


def fingerprints_from_known_hosts(output: str) -> set[str]:
    fingerprints: set[str] = set()
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        offset = 1 if fields and fields[0].startswith("@") else 0
        if len(fields) < offset + 3:
            continue
        try:
            key_bytes = base64.b64decode(fields[offset + 2], validate=True)
        except (ValueError, base64.binascii.Error):
            continue
        digest = base64.b64encode(hashlib.sha256(key_bytes).digest()).decode("ascii")
        fingerprints.add("SHA256:" + digest.rstrip("="))
    return fingerprints


def client_public_fingerprint(identity: pathlib.Path) -> str:
    result = run_external(
        ["ssh-keygen", "-y", "-f", str(identity)],
        capture=True,
        display=f"ssh-keygen -y -f {identity} <public-output-captured>",
    )
    if result.returncode != 0:
        raise YunError(result.stderr.strip() or f"cannot read public identity: {identity}")
    public_line = result.stdout.strip()
    fields = public_line.split()
    if len(fields) < 2 or fields[0] != "ssh-rsa" or "\n" in public_line:
        raise YunError("identity PEM does not contain one RSA public key")
    fingerprints = fingerprints_from_known_hosts(f"client {fields[0]} {fields[1]}\n")
    if len(fingerprints) != 1:
        raise YunError("cannot fingerprint identity PEM")
    return next(iter(fingerprints))


def bundle_cache_path(name: str) -> pathlib.Path:
    validate_target_name(name)
    path = (registry_path().parent / "known_hosts" / f"{name}.known_hosts").resolve()
    try:
        path.relative_to(SKILL_ROOT)
    except ValueError:
        return path
    raise YunError("bundle cache must remain outside the installed skill directory")


def encode_bundle_payload(payload: dict[str, Any]) -> bytes:
    raw = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    token = base64.urlsafe_b64encode(raw).rstrip(b"=")
    header = BUNDLE_PREFIX + token + b"\n"
    if len(header) > BUNDLE_MAX_HEADER_BYTES:
        raise YunError("self-describing PEM metadata is too large")
    return header


def read_bundle_payload(identity: pathlib.Path) -> dict[str, Any]:
    identity = identity.expanduser().resolve()
    if not identity.is_file() or identity.suffix.lower() != ".pem":
        raise YunError(f"self-describing PEM is missing: {identity}")
    if identity.stat().st_size > MAX_PRIVATE_KEY_BYTES:
        raise YunError("identity PEM exceeds the 1 MiB safety limit")
    with identity.open("rb") as stream:
        header = stream.readline(BUNDLE_MAX_HEADER_BYTES + 1)
    if len(header) > BUNDLE_MAX_HEADER_BYTES:
        raise YunError("self-describing PEM metadata header is too large")
    if not header.startswith(BUNDLE_PREFIX):
        raise YunError("PEM has no YUN-BUNDLE-V1 metadata; run bundle-pem first")
    if not header.endswith(b"\n"):
        raise YunError("self-describing PEM metadata header is truncated")
    token = header[len(BUNDLE_PREFIX) :].strip()
    if not token or re.fullmatch(rb"[A-Za-z0-9_-]+", token) is None:
        raise YunError("self-describing PEM metadata encoding is invalid")
    padding = b"=" * ((4 - len(token) % 4) % 4)
    try:
        decoded = base64.urlsafe_b64decode(token + padding)
        payload = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise YunError("self-describing PEM metadata cannot be decoded") from exc
    if not isinstance(payload, dict):
        raise YunError("self-describing PEM metadata must be an object")
    if encode_bundle_payload(payload) != header:
        raise YunError("self-describing PEM metadata is not canonical")
    return payload


def validate_bundle_payload(
    payload: dict[str, Any], identity: pathlib.Path
) -> tuple[str, dict[str, Any], str]:
    if set(payload) != BUNDLE_KEYS or payload.get("schema_version") != BUNDLE_SCHEMA_VERSION:
        raise YunError("unsupported or malformed self-describing PEM schema")
    name = payload.get("name")
    if not isinstance(name, str):
        raise YunError("self-describing PEM requires a target name")
    validate_target_name(name)
    connection = payload.get("connection")
    if not isinstance(connection, dict) or not (
        BUNDLE_CONNECTION_KEYS <= set(connection) <= BUNDLE_CONNECTION_KEYS | {"platform"}
    ):
        raise YunError("self-describing PEM has malformed connection metadata")
    known_hosts_line = payload.get("known_hosts_line")
    if (
        not isinstance(known_hosts_line, str)
        or not known_hosts_line
        or len(known_hosts_line) > 4096
        or any(character in known_hosts_line for character in "\r\n\x00")
    ):
        raise YunError("self-describing PEM has an invalid host-key line")
    host_fingerprint = payload.get("host_key_sha256")
    client_fingerprint = payload.get("client_key_sha256")
    if not isinstance(host_fingerprint, str) or not HOST_FINGERPRINT_PATTERN.fullmatch(
        host_fingerprint
    ):
        raise YunError("self-describing PEM has an invalid host fingerprint")
    if not isinstance(client_fingerprint, str) or not HOST_FINGERPRINT_PATTERN.fullmatch(
        client_fingerprint
    ):
        raise YunError("self-describing PEM has an invalid client fingerprint")

    roles = connection.get("roles")
    target: dict[str, Any] = {
        "description": connection.get("description"),
        "hostname": connection.get("hostname"),
        "port": connection.get("port"),
        "user": connection.get("user"),
        "identity_file": str(identity.expanduser().resolve()),
        "known_hosts_file": str(bundle_cache_path(name)),
        "expected_host_key_sha256": host_fingerprint,
        "roles": roles,
        "protected": connection.get("protected"),
        "compute_backend": "tmux" if isinstance(roles, list) and "compute" in roles else None,
        "job_root": JOB_ROOT if isinstance(roles, list) and "compute" in roles else None,
    }
    if "platform" in connection:
        target["platform"] = connection["platform"]
    validate_target(name, target)
    resolved_connection_files(target, require_exists=False)
    fields = known_hosts_line.split()
    if (
        len(fields) != 3
        or fields[0] != host_lookup(target)
        or fields[1] != "ssh-ed25519"
        or fingerprints_from_known_hosts(known_hosts_line) != {host_fingerprint}
    ):
        raise YunError("embedded ED25519 host key does not match target and fingerprint")
    return name, target, known_hosts_line


def verified_host_key_line(target: dict[str, Any]) -> str:
    _, known_hosts = resolved_connection_files(target, require_exists=True)
    result = run_external(
        ["ssh-keygen", "-F", host_lookup(target), "-f", str(known_hosts)],
        capture=True,
    )
    if result.returncode not in (0, 1):
        raise YunError(result.stderr.strip() or "known-host lookup failed")
    expected = str(target["expected_host_key_sha256"])
    matches: set[str] = set()
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        offset = 1 if fields and fields[0].startswith("@") else 0
        if len(fields) < offset + 3 or fields[offset + 1] != "ssh-ed25519":
            continue
        normalized = f"{host_lookup(target)} ssh-ed25519 {fields[offset + 2]}"
        if fingerprints_from_known_hosts(normalized) == {expected}:
            matches.add(normalized)
    if len(matches) != 1:
        raise YunError("expected exactly one verified ED25519 host key for bundling")
    return next(iter(matches))


def build_bundle_payload(name: str, target: dict[str, Any]) -> dict[str, Any]:
    identity, _ = resolved_connection_files(target, require_exists=True)
    return {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "name": name,
        "connection": {
            **({"platform": target["platform"]} if "platform" in target else {}),
            "description": target["description"],
            "hostname": target["hostname"],
            "port": target["port"],
            "user": target["user"],
            "roles": target["roles"],
            "protected": target["protected"],
        },
        "known_hosts_line": verified_host_key_line(target),
        "host_key_sha256": target["expected_host_key_sha256"],
        "client_key_sha256": client_public_fingerprint(identity),
    }


def write_bundled_identity(
    identity: pathlib.Path, header: bytes, expected_fingerprint: str
) -> None:
    identity = identity.expanduser().resolve()
    if identity.stat().st_size > MAX_PRIVATE_KEY_BYTES:
        raise YunError("identity PEM exceeds the 1 MiB safety limit")
    with identity.open("rb") as source:
        first_line = source.readline(BUNDLE_MAX_HEADER_BYTES + 1)
    if first_line.startswith(BUNDLE_PREFIX):
        source_offset = len(first_line)
    elif first_line in (
        b"-----BEGIN RSA PRIVATE KEY-----\n",
        b"-----BEGIN RSA PRIVATE KEY-----\r\n",
    ):
        source_offset = 0
    else:
        raise YunError("identity is not a supported RSA PEM or YUN-BUNDLE-V1 file")

    handle, temporary_name = tempfile.mkstemp(
        prefix=f".{identity.name}.bundle-", suffix=".pem", dir=identity.parent
    )
    os.close(handle)
    temporary = pathlib.Path(temporary_name)
    try:
        restrict_local_file(temporary)
        with identity.open("rb") as source, temporary.open("wb") as candidate:
            source.seek(source_offset)
            candidate.write(header)
            shutil.copyfileobj(source, candidate, length=64 * 1024)
            candidate.flush()
            os.fsync(candidate.fileno())
        if client_public_fingerprint(temporary) != expected_fingerprint:
            raise YunError("bundled PEM candidate changed the client public identity")
        os.replace(temporary, identity)
        restrict_local_file(identity)
    finally:
        if temporary.exists():
            temporary.unlink()


def resolved_connection_files(
    target: dict[str, Any], *, require_exists: bool
) -> tuple[pathlib.Path, pathlib.Path]:
    identity = pathlib.Path(str(target["identity_file"])).expanduser().resolve()
    known_hosts = pathlib.Path(str(target["known_hosts_file"])).expanduser().resolve()
    for label, path in (("identity PEM", identity), ("known-hosts file", known_hosts)):
        try:
            path.relative_to(SKILL_ROOT)
        except ValueError:
            pass
        else:
            raise YunError(f"{label} must remain outside the installed skill directory")
        if require_exists and not path.is_file():
            raise YunError(f"{label} is missing: {path}")
    return identity, known_hosts


def host_lookup(target: dict[str, Any]) -> str:
    hostname = str(target["hostname"])
    port = int(target["port"])
    return hostname if port == 22 else f"[{hostname}]:{port}"


def pinned_host_fingerprints(target: dict[str, Any]) -> set[str]:
    _, known_hosts = resolved_connection_files(target, require_exists=True)
    result = run_external(
        ["ssh-keygen", "-F", host_lookup(target), "-f", str(known_hosts)],
        capture=True,
    )
    if result.returncode not in (0, 1):
        raise YunError(result.stderr.strip() or f"known-host lookup failed: {known_hosts}")
    return fingerprints_from_known_hosts(result.stdout)


def verify_target_payload(name: str, target: dict[str, Any]) -> dict[str, Any]:
    validate_target(name, target)
    resolved_connection_files(target, require_exists=True)
    expected_fingerprint = str(target["expected_host_key_sha256"])
    if expected_fingerprint not in pinned_host_fingerprints(target):
        raise YunError(f"pinned host-key fingerprint mismatch for {name}")
    return target


def verify_target(name: str) -> dict[str, Any]:
    return verify_target_payload(name, get_target(name))


def require_role(target: dict[str, Any], role: str) -> None:
    if role not in target.get("roles", []):
        raise YunError(f"target does not provide role: {role}")


def require_protected_confirmation(
    name: str, target: dict[str, Any], confirmation: str | None
) -> None:
    if target.get("protected") and confirmation != name:
        raise YunError(f"protected target requires --confirm-target {name}")


def connection_options(target: dict[str, Any]) -> list[str]:
    identity, known_hosts = resolved_connection_files(target, require_exists=True)
    return [
        "-F",
        "none",
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "GlobalKnownHostsFile=none",
        "-o",
        "UpdateHostKeys=no",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ServerAliveInterval=30",
        "-o",
        "ServerAliveCountMax=3",
        "-i",
        str(identity),
    ]


def destination(target: dict[str, Any], *, scp: bool = False) -> str:
    hostname = str(target["hostname"])
    if scp and ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    return f"{target['user']}@{hostname}"


def scp_argv(target: dict[str, Any], *, recursive: bool = False) -> list[str]:
    argv = ["scp", *connection_options(target), "-P", str(target["port"])]
    if recursive:
        argv.append("-r")
    return argv


def ssh_run(
    target: dict[str, Any],
    remote_command: str,
    *,
    capture: bool = False,
    dry_run: bool = False,
) -> subprocess.CompletedProcess[str]:
    remote = destination(target)
    return run_external(
        [
            "ssh",
            *connection_options(target),
            "-p",
            str(target["port"]),
            remote,
            remote_command,
        ],
        capture=capture,
        dry_run=dry_run,
        display=f"ssh {remote}:{target['port']} <remote-command>",
    )


def ssh_interactive(target: dict[str, Any], remote_command: str) -> subprocess.CompletedProcess[str]:
    """Run one user-facing, TTY-bound command through the pinned target path."""
    remote = destination(target)
    return run_external(
        [
            "ssh",
            *connection_options(target),
            "-tt",
            "-p",
            str(target["port"]),
            remote,
            remote_command,
        ],
        display=f"ssh {remote}:{target['port']} <interactive-authorized-command>",
    )


def validate_job_id(job_id: str) -> str:
    if not JOB_ID_PATTERN.fullmatch(job_id):
        raise YunError("invalid job ID")
    return job_id


def job_paths(target: dict[str, Any], job_id: str) -> tuple[str, str]:
    if target.get("job_root") != JOB_ROOT:
        raise YunError("invalid registered job root")
    validate_job_id(job_id)
    return f"$HOME/{JOB_ROOT}/{job_id}", f"~/{JOB_ROOT}/{job_id}"


def slug(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return (normalized or "job")[:24].rstrip("-")


def new_job_id(name: str) -> str:
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{timestamp}-{slug(name)}-{secrets.token_hex(3)}"


def redact(text: str) -> str:
    patterns = (
        (re.compile(r"(?i)(authorization:\s*bearer\s+)\S+"), r"\1[REDACTED]"),
        (re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"), "[REDACTED_KEY]"),
        (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
        (
            re.compile(r"(?i)((?:api[_-]?key|token|password|secret)\s*[=:]\s*)\S+"),
            r"\1[REDACTED]",
        ),
    )
    for pattern, replacement in patterns:
        text = pattern.sub(replacement, text)
    return text


def cmd_init(args: argparse.Namespace) -> int:
    path = registry_path()
    if path.exists():
        load_registry_payload()
        print(f"registry={path}")
        print("state=existing")
        return 0
    write_registry(empty_registry(), dry_run=args.dry_run)
    print(f"registry={path}")
    print("state=would-create" if args.dry_run else "state=created")
    return 0


def cmd_registry_path(args: argparse.Namespace) -> int:
    del args
    print(registry_path())
    return 0


def cmd_targets(args: argparse.Namespace) -> int:
    targets = load_registry()
    if args.json:
        print(json.dumps(targets, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if not targets:
        print("no targets registered")
        return 0
    for name, target in sorted(targets.items()):
        roles = ",".join(target["roles"])
        protection = "protected" if target["protected"] else "standard"
        print(
            f"{name}\t{target['user']}@{target['hostname']}:{target['port']}\t"
            f"{roles}\t{protection}\t"
            f"{target['description']}"
        )
    return 0


def cmd_register(args: argparse.Namespace) -> int:
    payload = load_registry_payload()
    name = validate_target_name(args.name)
    roles = list(dict.fromkeys(args.role))
    identity_file = pathlib.Path(
        args.pem or pathlib.Path.home() / ".ssh" / f"yun_{name}.pem"
    ).expanduser().resolve()
    known_hosts_file = pathlib.Path(
        args.known_hosts or pathlib.Path.home() / ".ssh" / f"yun_{name}.known_hosts"
    ).expanduser().resolve()
    target: dict[str, Any] = {
        "description": args.description or name,
        "hostname": args.host,
        "port": args.port,
        "user": args.user,
        "identity_file": str(identity_file),
        "known_hosts_file": str(known_hosts_file),
        "expected_host_key_sha256": args.host_fingerprint,
        "roles": roles,
        "protected": bool(args.protected),
        "compute_backend": "tmux" if "compute" in roles else None,
        "job_root": JOB_ROOT if "compute" in roles else None,
    }
    if getattr(args, "platform", "linux") == "windows":
        target["platform"] = "windows"
    validate_target(name, target)
    if name in payload["targets"] and args.confirm_replace != name:
        raise YunError(f"replacing target requires --confirm-replace {name}")
    payload["targets"][name] = target
    validate_registry(payload)
    verify_target_payload(name, target)
    write_registry(payload, dry_run=args.dry_run)
    print(f"registered={name}")
    print(f"registry={registry_path()}")
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    key_directory = pathlib.Path(args.directory).expanduser().resolve()
    key_name = validate_target_name(args.name)
    private_key = key_directory / f"yun_{key_name}.pem"
    key_args = ["-t", "rsa", "-b", "4096", "-m", "PEM"]
    public_key = pathlib.Path(f"{private_key}.pub")
    if private_key.exists() or public_key.exists():
        raise YunError(f"refusing to overwrite existing key pair: {private_key}")
    comment = f"yun:{key_name}:{dt.date.today().isoformat()}"
    command = [
        "ssh-keygen",
        "-q",
        *key_args,
        "-f",
        str(private_key),
        "-C",
        comment,
        "-N",
        "",
    ]
    if args.dry_run:
        run_external(command, dry_run=True)
        print(f"private_key={private_key}")
        print(f"public_key={public_key}")
        return 0

    key_directory.mkdir(parents=True, exist_ok=True)
    result = run_external(command)
    if result.returncode != 0:
        return result.returncode
    if not private_key.is_file() or not public_key.is_file():
        raise YunError("ssh-keygen completed without both key files")
    restrict_local_file(private_key)
    if os.name != "nt":
        public_key.chmod(0o644)

    fingerprint = run_external(
        ["ssh-keygen", "-lf", str(public_key), "-E", "sha256"], capture=True
    )
    if fingerprint.returncode != 0:
        raise YunError(fingerprint.stderr.strip() or "fingerprint generation failed")
    print(f"private_key={private_key}")
    print(f"public_key={public_key}")
    print(f"public_fingerprint={fingerprint.stdout.strip()}")
    return 0


def cmd_bundle_pem(args: argparse.Namespace) -> int:
    target = verify_target(args.target)
    require_protected_confirmation(args.target, target, args.confirm_target)
    identity, _ = resolved_connection_files(target, require_exists=True)
    payload = build_bundle_payload(args.target, target)
    validate_bundle_payload(payload, identity)
    header = encode_bundle_payload(payload)

    with identity.open("rb") as stream:
        already_bundled = stream.readline(len(BUNDLE_PREFIX)).startswith(BUNDLE_PREFIX)
    state = "created"
    if already_bundled:
        existing = read_bundle_payload(identity)
        validate_bundle_payload(existing, identity)
        if existing == payload:
            print(f"bundled={args.target}")
            print("state=existing")
            return 0
        if args.confirm_rebind != args.target:
            raise YunError(f"rebinding PEM metadata requires --confirm-rebind {args.target}")
        state = "rebound"

    if args.dry_run:
        print(f"would_bundle={args.target}")
        print(f"identity_file={identity}")
        print(f"state=would-{state}")
        return 0
    write_bundled_identity(identity, header, str(payload["client_key_sha256"]))
    validated = read_bundle_payload(identity)
    validate_bundle_payload(validated, identity)
    print(f"bundled={args.target}")
    print(f"identity_file={identity}")
    print(f"state={state}")
    return 0


def cmd_import_pem(args: argparse.Namespace) -> int:
    identity = pathlib.Path(args.pem).expanduser().resolve()
    bundle = read_bundle_payload(identity)
    name, target, known_hosts_line = validate_bundle_payload(bundle, identity)
    if not args.dry_run:
        restrict_local_file(identity)
    if client_public_fingerprint(identity) != str(bundle["client_key_sha256"]):
        raise YunError("PEM private identity does not match its embedded client fingerprint")

    registry = load_registry_or_empty()
    existing_target = registry["targets"].get(name)
    cache = pathlib.Path(str(target["known_hosts_file"]))
    desired_cache = known_hosts_line + "\n"
    existing_cache: str | None = None
    if cache.exists():
        try:
            existing_cache = cache.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise YunError(f"existing host-key cache is not UTF-8: {cache}") from exc

    target_changes = existing_target is not None and existing_target != target
    cache_changes = existing_cache is not None and existing_cache != desired_cache
    if (target_changes or cache_changes) and args.confirm_replace != name:
        raise YunError(f"import replacement requires --confirm-replace {name}")

    if existing_target == target and existing_cache == desired_cache:
        verify_target_payload(name, target)
        print(f"imported={name}")
        print("state=existing")
        return 0

    candidate_registry = {
        "schema_version": registry["schema_version"],
        "targets": dict(registry["targets"]),
    }
    candidate_registry["targets"][name] = target
    validate_registry(candidate_registry)
    if args.dry_run:
        print(f"would_import={name}")
        print(f"identity_file={identity}")
        print(f"registry={registry_path()}")
        return 0

    cache_existed = cache.exists()
    try:
        write_public_text(cache, desired_cache)
        verify_target_payload(name, target)
        write_registry(candidate_registry)
    except Exception:
        if cache_existed and existing_cache is not None:
            write_public_text(cache, existing_cache)
        elif not cache_existed and cache.exists():
            cache.unlink()
        raise
    print(f"imported={name}")
    print(f"identity_file={identity}")
    print(f"registry={registry_path()}")
    print("state=replaced" if target_changes or cache_changes else "state=created")
    return 0


def powershell_literal(value: str) -> str:
    if "\x00" in value:
        raise YunError("PowerShell arguments cannot contain NUL")
    return "'" + value.replace("'", "''") + "'"


def powershell_command(source: str) -> str:
    # EncodedCommand survives both cmd.exe and PowerShell as the sshd default shell.
    # Keep under cmd.exe's 8191-character command limit, including SSH shell overhead.
    wrapped = """$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
$global:LASTEXITCODE = 0
try {
""" + source + """
exit $global:LASTEXITCODE
} catch {
[Console]::Error.WriteLine($_.Exception.Message)
exit 1
}
"""
    encoded = base64.b64encode(wrapped.encode("utf-16le")).decode("ascii")
    command = "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand " + encoded
    if len(command) > 7500:
        raise YunError("PowerShell command is too long; upload a .ps1 and exec powershell.exe -File PATH")
    return command


WINDOWS_PROBE = r"""
$os = Get-CimInstance Win32_OperatingSystem
$disk = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='" + $env:SystemDrive + "'")
if ($null -eq $disk) { throw 'System drive information unavailable' }
$info = [ordered]@{
    hostname = [Environment]::MachineName
    user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    platform = 'windows'
    kernel = $os.Caption + ' ' + $os.Version
    uptime_seconds = [math]::Floor(((Get-Date) - $os.LastBootUpTime).TotalSeconds)
    root_disk = [ordered]@{ drive = $env:SystemDrive; total_bytes = $disk.Size; free_bytes = $disk.FreeSpace }
    memory = [ordered]@{ total_kib = $os.TotalVisibleMemorySize; free_kib = $os.FreePhysicalMemory }
    scheduler = 'none'
}
'YUN_PROBE_OK'
$info | ConvertTo-Json -Compress -Depth 3
""".strip()


def sftp_literal(path: str) -> str:
    # Exactly one file: no globs, control characters, or embedded batch commands.
    if not path or any(ord(c) < 32 for c in path) or any(c in path for c in '*?[]'):
        raise YunError("SFTP requires a literal file path without globs or control characters")
    return '"' + path.replace('\\', '\\\\').replace('"', '\\"') + '"'


def windows_transfer(
    target: dict[str, Any], local: pathlib.Path, remote: str, *, upload: bool, dry_run: bool
) -> int:
    remote = remote.replace('\\', '/')
    if not re.match(r'^[A-Za-z]:/', remote) or remote.endswith('/') or any(
        part in ('.', '..') for part in remote.split('/')
    ) or ':' in remote[2:] or '"' in remote:
        raise YunError("Windows remote file path must be absolute, e.g. C:/Users/name/result.json")
    local_literal = sftp_literal(local.as_posix())
    remote_literal = sftp_literal('/' + remote)
    if not upload and not dry_run:
        local.parent.mkdir(parents=True, exist_ok=True)
    operation = f"put {local_literal} {remote_literal}" if upload else f"get {remote_literal} {local_literal}"
    return run_external(
        ["sftp", *connection_options(target), "-P", str(target['port']), "-b", "-", destination(target, scp=True)],
        input_text=operation + "\nbye\n",
        dry_run=dry_run,
        display=f"sftp {destination(target)} <one-file-{'upload' if upload else 'download'}>",
    ).returncode


def cmd_probe(args: argparse.Namespace) -> int:
    target = verify_target(args.target)
    if target.get("platform", "linux") == "windows":
        return ssh_run(target, powershell_command(WINDOWS_PROBE), dry_run=args.dry_run).returncode
    remote = r"""
set -u
printf 'YUN_PROBE_OK\n'
printf 'hostname='; hostname
printf 'user='; id -un
printf 'kernel='; uname -sr
printf 'uptime='; uptime -p
printf 'root_disk='; df -h / | awk 'NR==2 {print $2","$3","$4","$5}'
printf 'memory='; LANG=C free -h | awk '/^Mem:/ {print $2","$3","$7}'
printf 'scheduler='; if command -v tmux >/dev/null 2>&1 && command -v setsid >/dev/null 2>&1; then echo tmux; else echo none; fi
printf 'gpu='; if command -v nvidia-smi >/dev/null 2>&1; then if gpu_info=$(nvidia-smi --query-gpu=name,memory.total --format=csv,noheader 2>/dev/null); then printf '%s\n' "$gpu_info" | paste -sd';' -; else echo unavailable; fi; else echo none; fi
""".strip()
    return ssh_run(target, remote, dry_run=args.dry_run).returncode


def cmd_exec(args: argparse.Namespace) -> int:
    target = verify_target(args.target)
    require_role(target, "server")
    if args.write:
        require_protected_confirmation(args.target, target, args.confirm_target)
    command = list(args.remote_command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        raise YunError("remote command is required after --")
    if target.get("platform", "linux") == "windows":
        # Native executable argv, never PowerShell source. Cmdlets/pipelines use exec-script.
        remote = powershell_command(
            "$yunStart = New-Object System.Diagnostics.ProcessStartInfo\n"
            + "$yunStart.UseShellExecute = $false\n"
            + "$yunStart.CreateNoWindow = $true\n"
            + "$yunStart.FileName = " + powershell_literal(command[0]) + "\n"
            + "$yunStart.Arguments = " + powershell_literal(subprocess.list2cmdline(command[1:])) + "\n"
            + "$yunProcess = [System.Diagnostics.Process]::Start($yunStart)\n"
            + "$yunProcess.WaitForExit()\nexit $yunProcess.ExitCode\n"
        )
    else:
        remote = shlex.join(command)
    return ssh_run(target, remote, dry_run=args.dry_run).returncode


def cmd_exec_script(args: argparse.Namespace) -> int:
    target = verify_target(args.target)
    require_role(target, "server")
    if args.write:
        require_protected_confirmation(args.target, target, args.confirm_target)
    if target.get("platform", "linux") != "windows":
        raise YunError("exec-script currently supports Windows PowerShell only")
    script = pathlib.Path(args.script).expanduser().resolve()
    if not script.is_file() or script.suffix.lower() != ".ps1":
        raise YunError("exec-script requires an existing UTF-8 .ps1 file")
    if script.stat().st_size > 2048:
        raise YunError("inline script exceeds 2 KiB; upload it, then exec powershell.exe -File PATH")
    try:
        source = script.read_text(encoding="utf-8-sig")
    except UnicodeError as exc:
        raise YunError("PowerShell script must be UTF-8") from exc
    return ssh_run(target, powershell_command(source), dry_run=args.dry_run).returncode


def cmd_sudo_authorize(args: argparse.Namespace) -> int:
    """Open a pinned terminal only for user-entered sudo credential caching.

    No password is accepted as an argument, read by this process, written to a
    file, or forwarded through stdin. This remains deliberately separate from
    ``exec`` so that authorization never also executes a deployment command.
    """
    target = verify_target(args.target)
    require_role(target, "server")
    require_protected_confirmation(args.target, target, args.confirm_target)
    if target.get("platform", "linux") == "windows":
        raise YunError("sudo-authorize is Linux-only; use an authorized Windows account")
    remote = "sudo -v && printf 'YUN_SUDO_AUTHORIZED\\n'"
    return ssh_interactive(target, remote).returncode


def valid_remote_path(value: str) -> str:
    if not value or value.startswith("-") or any(character in value for character in "\r\n\x00"):
        raise YunError("invalid remote path")
    return value


def cmd_upload(args: argparse.Namespace) -> int:
    target = verify_target(args.target)
    require_role(target, "server")
    require_protected_confirmation(args.target, target, args.confirm_target)
    local = pathlib.Path(args.local).expanduser().resolve()
    if not local.is_file():
        raise YunError(f"local upload file is missing: {local}")
    remote = valid_remote_path(args.remote)
    if target.get("platform", "linux") == "windows":
        return windows_transfer(target, local, remote, upload=True, dry_run=args.dry_run)
    return run_external(
        [*scp_argv(target), str(local), f"{destination(target, scp=True)}:{remote}"],
        dry_run=args.dry_run,
        display=f"scp <local-file> {destination(target, scp=True)}:<remote-path>",
    ).returncode


def cmd_download(args: argparse.Namespace) -> int:
    target = verify_target(args.target)
    require_role(target, "server")
    remote = valid_remote_path(args.remote)
    local_destination = pathlib.Path(args.local).expanduser().resolve()
    if target.get("platform", "linux") == "windows":
        return windows_transfer(target, local_destination, remote, upload=False, dry_run=args.dry_run)
    if not args.dry_run:
        local_destination.parent.mkdir(parents=True, exist_ok=True)
    return run_external(
        [
            *scp_argv(target),
            f"{destination(target, scp=True)}:{remote}",
            str(local_destination),
        ],
        dry_run=args.dry_run,
        display=f"scp {destination(target, scp=True)}:<remote-path> <local-file>",
    ).returncode


def cmd_submit(args: argparse.Namespace) -> int:
    target = verify_target(args.target)
    require_role(target, "compute")
    require_protected_confirmation(args.target, target, args.confirm_target)
    if target.get("compute_backend") != "tmux":
        raise YunError("this CLI submits only to registered tmux targets")
    script = pathlib.Path(args.script).expanduser().resolve()
    if not script.is_file():
        raise YunError(f"job script is missing: {script}")
    if script.stat().st_size > 10 * 1024 * 1024:
        raise YunError("job script exceeds 10 MiB")
    if not RUNNER_PATH.is_file():
        raise YunError("bundled remote runner is missing")

    job_id = new_job_id(args.name or script.stem)
    shell_path, scp_path = job_paths(target, job_id)
    create = f'''set -eu
umask 077
root="{shell_path}"
test ! -e "$root"
mkdir -p "$root/results"
'''
    result = ssh_run(target, create, dry_run=args.dry_run)
    if result.returncode != 0:
        return result.returncode

    for source, name in ((script, "job.sh"), (RUNNER_PATH, "runner.sh")):
        result = run_external(
            [
                *scp_argv(target),
                str(source),
                f"{destination(target, scp=True)}:{scp_path}/{name}",
            ],
            dry_run=args.dry_run,
            display=f"scp <job-file> {destination(target, scp=True)}:<job-path>",
        )
        if result.returncode != 0:
            return result.returncode

    session = f"yun-{job_id}"
    start = f'''set -eu
root="{shell_path}"
session={shlex.quote(session)}
command -v tmux >/dev/null
command -v setsid >/dev/null
chmod 700 "$root/job.sh" "$root/runner.sh"
test ! -e "$root/status"
tmux new-session -d -s "$session" "bash \"$root/runner.sh\" \"$root\""
'''
    result = ssh_run(target, start, capture=True, dry_run=args.dry_run)
    if result.returncode != 0:
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="")
        return result.returncode
    print(job_id)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    target = verify_target(args.target)
    require_role(target, "compute")
    shell_path, _ = job_paths(target, args.job_id)
    session = f"yun-{args.job_id}"
    remote = f'''set -eu
root="{shell_path}"
test -d "$root"
for field in status started_at finished_at exit_code runner_pid child_pid; do
  if test -f "$root/$field"; then printf '%s=' "$field"; cat "$root/$field"; fi
done
if tmux has-session -t {shlex.quote(session)} 2>/dev/null; then echo session=running; else echo session=absent; fi
printf 'size='; du -sh "$root" | awk '{{print $1}}'
'''
    return ssh_run(target, remote, dry_run=args.dry_run).returncode


def cmd_jobs(args: argparse.Namespace) -> int:
    target = verify_target(args.target)
    require_role(target, "compute")
    remote = f'''set -eu
base="$HOME/{JOB_ROOT}"
test -d "$base" || exit 0
find "$base" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort | while IFS= read -r job; do
  case "$job" in *[!A-Za-z0-9._-]*|'') continue;; esac
  state=$(cat "$base/$job/status" 2>/dev/null || echo unknown)
  started=$(cat "$base/$job/started_at" 2>/dev/null || echo -)
  printf '%s\t%s\t%s\n' "$job" "$state" "$started"
done
'''
    return ssh_run(target, remote, dry_run=args.dry_run).returncode


def cmd_logs(args: argparse.Namespace) -> int:
    target = verify_target(args.target)
    require_role(target, "compute")
    shell_path, _ = job_paths(target, args.job_id)
    lines = max(1, min(args.lines, 5000))
    remote = f'''set -eu
root="{shell_path}"
test -d "$root"
printf '%s\n' '--- stdout ---'
test ! -f "$root/stdout.log" || tail -n {lines} "$root/stdout.log"
printf '%s\n' '--- stderr ---'
test ! -f "$root/stderr.log" || tail -n {lines} "$root/stderr.log"
'''
    result = ssh_run(target, remote, capture=True, dry_run=args.dry_run)
    if result.stdout:
        print(redact(result.stdout), end="")
    if result.stderr:
        print(redact(result.stderr), file=sys.stderr, end="")
    return result.returncode


def cmd_cancel(args: argparse.Namespace) -> int:
    target = verify_target(args.target)
    require_role(target, "compute")
    require_protected_confirmation(args.target, target, args.confirm_target)
    shell_path, _ = job_paths(target, args.job_id)
    session = f"yun-{args.job_id}"
    remote = f'''set -eu
root="{shell_path}"
test -d "$root"
state=$(cat "$root/status" 2>/dev/null || echo unknown)
case "$state" in succeeded|failed|cancelled) printf 'already_terminal=%s\n' "$state"; exit 0;; esac
: > "$root/cancel_requested"
if tmux has-session -t {shlex.quote(session)} 2>/dev/null; then
  tmux send-keys -t {shlex.quote(session)} C-c
  sleep 1
  tmux kill-session -t {shlex.quote(session)} 2>/dev/null || true
fi
if test -s "$root/child_pid"; then
  pid=$(cat "$root/child_pid")
  case "$pid" in *[!0-9]*|'') ;; *)
    sid=$(ps -o sid= -p "$pid" 2>/dev/null | tr -d ' ')
    if test "$sid" = "$pid"; then kill -TERM -- "-$pid" 2>/dev/null || true; fi
  esac
fi
printf 'cancel_requested=%s\n' {shlex.quote(args.job_id)}
'''
    return ssh_run(target, remote, dry_run=args.dry_run).returncode


def cmd_fetch(args: argparse.Namespace) -> int:
    target = verify_target(args.target)
    require_role(target, "compute")
    _, scp_path = job_paths(target, args.job_id)
    check = ssh_run(
        target,
        f'test -d "$HOME/{JOB_ROOT}/{args.job_id}/results"',
        dry_run=args.dry_run,
    )
    if check.returncode != 0:
        return check.returncode
    local_destination = pathlib.Path(args.destination).expanduser().resolve() / args.job_id
    if not args.dry_run:
        local_destination.parent.mkdir(parents=True, exist_ok=True)
    return run_external(
        [
            *scp_argv(target, recursive=True),
            f"{destination(target, scp=True)}:{scp_path}/results",
            str(local_destination),
        ],
        dry_run=args.dry_run,
        display=f"scp -r {destination(target, scp=True)}:<results> <destination>",
    ).returncode


def cmd_cleanup(args: argparse.Namespace) -> int:
    target = verify_target(args.target)
    require_role(target, "compute")
    require_protected_confirmation(args.target, target, args.confirm_target)
    validate_job_id(args.job_id)
    if args.confirm_job != args.job_id:
        raise YunError(f"cleanup requires --confirm-job {args.job_id}")
    shell_path, _ = job_paths(target, args.job_id)
    session = f"yun-{args.job_id}"
    remote = f'''set -eu
base=$(readlink -f "$HOME/{JOB_ROOT}")
job=$(readlink -f "{shell_path}")
test -d "$job"
case "$job" in "$base"/*) ;; *) echo 'unsafe job path' >&2; exit 65;; esac
test "${{job##*/}}" = {shlex.quote(args.job_id)}
state=$(cat "$job/status" 2>/dev/null || echo unknown)
case "$state" in succeeded|failed|cancelled) ;; *) echo "job is not terminal: $state" >&2; exit 66;; esac
if tmux has-session -t {shlex.quote(session)} 2>/dev/null; then echo 'job session is still active' >&2; exit 67; fi
rm -rf -- "$job"
test ! -e "$job"
printf 'cleaned=%s\n' {shlex.quote(args.job_id)}
'''
    return ssh_run(target, remote, dry_run=args.dry_run).returncode


def add_protected_confirmation(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--confirm-target")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="云：self-describing PEM SSH control and durable remote jobs"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="print external actions without running them"
    )
    subparsers = parser.add_subparsers(dest="command_name", required=True)

    initialize = subparsers.add_parser("init", help="create the user-local registry")
    initialize.set_defaults(func=cmd_init)

    registry = subparsers.add_parser("registry-path", help="print the registry path")
    registry.set_defaults(func=cmd_registry_path)

    targets = subparsers.add_parser("targets", help="list registered targets")
    targets.add_argument("--json", action="store_true")
    targets.set_defaults(func=cmd_targets)

    register = subparsers.add_parser("register", help="validate and register one target")
    register.add_argument("name")
    register.add_argument("--host", required=True)
    register.add_argument("--port", type=int, default=22)
    register.add_argument("--user", required=True)
    register.add_argument("--platform", choices=("linux", "windows"), default="linux")
    register.add_argument("--pem")
    register.add_argument("--known-hosts")
    register.add_argument("--host-fingerprint", required=True)
    register.add_argument(
        "--role", action="append", choices=sorted(ALLOWED_ROLES), required=True
    )
    register.add_argument("--description")
    register.add_argument("--protected", action="store_true")
    register.add_argument("--confirm-replace")
    register.set_defaults(func=cmd_register)

    keygen = subparsers.add_parser("keygen", help="generate a per-target SSH key pair")
    keygen.add_argument("name")
    keygen.add_argument("--directory", default=str(pathlib.Path.home() / ".ssh"))
    keygen.set_defaults(func=cmd_keygen)

    bundle = subparsers.add_parser(
        "bundle-pem", help="embed verified public connection metadata in one PEM"
    )
    bundle.add_argument("target")
    add_protected_confirmation(bundle)
    bundle.add_argument("--confirm-rebind")
    bundle.set_defaults(func=cmd_bundle_pem)

    import_pem = subparsers.add_parser(
        "import-pem", help="rebuild a target and host-key cache from one bundled PEM"
    )
    import_pem.add_argument("pem")
    import_pem.add_argument("--confirm-replace")
    import_pem.set_defaults(func=cmd_import_pem)

    probe = subparsers.add_parser("probe", help="run a read-only identity/readiness probe")
    probe.add_argument("target")
    probe.set_defaults(func=cmd_probe)

    execute = subparsers.add_parser("exec", help="run a declared remote command")
    execute.add_argument("target")
    intent = execute.add_mutually_exclusive_group(required=True)
    intent.add_argument("--read-only", action="store_true")
    intent.add_argument("--write", action="store_true")
    add_protected_confirmation(execute)
    execute.add_argument("remote_command", nargs="+")
    execute.set_defaults(func=cmd_exec)

    script = subparsers.add_parser("exec-script", help="run a bounded UTF-8 PowerShell script on Windows")
    script.add_argument("target")
    script.add_argument("script")
    intent = script.add_mutually_exclusive_group(required=True)
    intent.add_argument("--read-only", action="store_true")
    intent.add_argument("--write", action="store_true")
    add_protected_confirmation(script)
    script.set_defaults(func=cmd_exec_script)

    sudo_authorize = subparsers.add_parser(
        "sudo-authorize",
        help="open a pinned interactive terminal for user-entered sudo authorization",
    )
    sudo_authorize.add_argument("target")
    add_protected_confirmation(sudo_authorize)
    sudo_authorize.set_defaults(func=cmd_sudo_authorize)

    upload = subparsers.add_parser("upload", help="upload one bounded file")
    upload.add_argument("target")
    upload.add_argument("local")
    upload.add_argument("remote")
    add_protected_confirmation(upload)
    upload.set_defaults(func=cmd_upload)

    download = subparsers.add_parser("download", help="download one bounded file")
    download.add_argument("target")
    download.add_argument("remote")
    download.add_argument("local")
    download.set_defaults(func=cmd_download)

    submit = subparsers.add_parser("submit", help="submit a durable tmux compute job")
    submit.add_argument("target")
    submit.add_argument("script")
    submit.add_argument("--name")
    add_protected_confirmation(submit)
    submit.set_defaults(func=cmd_submit)

    status = subparsers.add_parser("status", help="show durable job state")
    status.add_argument("target")
    status.add_argument("job_id")
    status.set_defaults(func=cmd_status)

    jobs = subparsers.add_parser("jobs", help="list durable jobs on a target")
    jobs.add_argument("target")
    jobs.set_defaults(func=cmd_jobs)

    logs = subparsers.add_parser("logs", help="show redacted job log tails")
    logs.add_argument("target")
    logs.add_argument("job_id")
    logs.add_argument("--lines", type=int, default=100)
    logs.set_defaults(func=cmd_logs)

    cancel = subparsers.add_parser("cancel", help="cancel a running compute job")
    cancel.add_argument("target")
    cancel.add_argument("job_id")
    add_protected_confirmation(cancel)
    cancel.set_defaults(func=cmd_cancel)

    fetch = subparsers.add_parser("fetch", help="download a job results directory")
    fetch.add_argument("target")
    fetch.add_argument("job_id")
    fetch.add_argument("destination")
    fetch.set_defaults(func=cmd_fetch)

    cleanup = subparsers.add_parser(
        "cleanup", help="remove one confirmed terminal job directory"
    )
    cleanup.add_argument("target")
    cleanup.add_argument("job_id")
    cleanup.add_argument("--confirm-job", required=True)
    add_protected_confirmation(cleanup)
    cleanup.set_defaults(func=cmd_cleanup)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        return int(args.func(args))
    except (YunError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
