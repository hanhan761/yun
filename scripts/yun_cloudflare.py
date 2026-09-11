#!/usr/bin/env python3
"""Cloudflare DNS adapter for yun.

The agent never handles or prints the API token. ``configure`` reads it from a
hidden terminal prompt, validates it, and stores it outside the Skill. On
Windows the stored value is protected with CurrentUser DPAPI.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import ctypes
from ctypes import wintypes
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


API_BASE = "https://api.cloudflare.com/client/v4"
SECRET_CONTEXT = b"yun-cloudflare-token-v1"
DNS_NAME_RE = re.compile(
    r"(?=^.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.IGNORECASE,
)


class CloudflareError(RuntimeError):
    pass


def _config_root() -> Path:
    override = os.environ.get("YUN_CONFIG_HOME")
    return Path(override).expanduser() if override else Path.home() / ".config" / "yun"


def _secret_path() -> Path:
    suffix = ".dpapi" if os.name == "nt" else ".token"
    return _config_root() / "secrets" / f"cloudflare-api-token{suffix}"


def _metadata_path() -> Path:
    return _config_root() / "cloudflare.json"


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, candidate = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    candidate_path = Path(candidate)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(candidate_path, mode)
        os.replace(candidate_path, path)
        os.chmod(path, mode)
        if os.name == "nt":
            _restrict_windows_acl(path.parent)
            _restrict_windows_acl(path)
    finally:
        if candidate_path.exists():
            candidate_path.unlink()


def _restrict_windows_acl(path: Path) -> None:
    identity = subprocess.run(
        ["whoami"], check=True, capture_output=True, text=True
    ).stdout.strip()
    result = subprocess.run(
        ["icacls", str(path), "/inheritance:r", "/grant:r", f"{identity}:(F)"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise CloudflareError(f"Could not restrict ACL for {path}")


if os.name == "nt":
    class _DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


    ctypes.windll.crypt32.CryptProtectData.restype = wintypes.BOOL
    ctypes.windll.crypt32.CryptUnprotectData.restype = wintypes.BOOL
    ctypes.windll.kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    ctypes.windll.kernel32.LocalFree.restype = wintypes.HLOCAL


    def _blob(data: bytes) -> tuple[_DataBlob, Any]:
        buffer = ctypes.create_string_buffer(data)
        return _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))), buffer


    def _dpapi(data: bytes, *, protect: bool) -> bytes:
        source, source_buffer = _blob(data)
        entropy, entropy_buffer = _blob(SECRET_CONTEXT)
        output = _DataBlob()
        flags = 0x1  # CRYPTPROTECT_UI_FORBIDDEN
        if protect:
            ok = ctypes.windll.crypt32.CryptProtectData(
                ctypes.byref(source),
                "yun cloudflare token",
                ctypes.byref(entropy),
                None,
                None,
                flags,
                ctypes.byref(output),
            )
        else:
            ok = ctypes.windll.crypt32.CryptUnprotectData(
                ctypes.byref(source),
                None,
                ctypes.byref(entropy),
                None,
                None,
                flags,
                ctypes.byref(output),
            )
        del source_buffer, entropy_buffer
        if not ok:
            raise CloudflareError("Windows DPAPI could not process the Cloudflare token")
        try:
            return ctypes.string_at(output.pbData, output.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(ctypes.cast(output.pbData, wintypes.HLOCAL))


def _protect_token(token: str) -> bytes:
    raw = token.encode("utf-8")
    if os.name == "nt":
        return b"YUN-CLOUDFLARE-DPAPI-V1\n" + base64.b64encode(_dpapi(raw, protect=True))
    return b"YUN-CLOUDFLARE-FILE-V1\n" + base64.b64encode(raw)


def _unprotect_token(payload: bytes) -> str:
    header, separator, body = payload.partition(b"\n")
    if not separator:
        raise CloudflareError("Cloudflare credential file has an invalid format")
    try:
        encoded = base64.b64decode(body, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise CloudflareError("Cloudflare credential file is corrupt") from exc
    if header == b"YUN-CLOUDFLARE-DPAPI-V1" and os.name == "nt":
        raw = _dpapi(encoded, protect=False)
    elif header == b"YUN-CLOUDFLARE-FILE-V1" and os.name != "nt":
        raw = encoded
    else:
        raise CloudflareError("Cloudflare credential belongs to another operating system")
    return raw.decode("utf-8")


def _load_token() -> str:
    path = _secret_path()
    if not path.is_file():
        raise CloudflareError("Cloudflare token is not configured; run configure in a local terminal")
    return _unprotect_token(path.read_bytes())


def _load_metadata() -> dict[str, Any]:
    path = _metadata_path()
    if not path.is_file():
        raise CloudflareError("Cloudflare metadata is not configured")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CloudflareError("Cloudflare metadata is unreadable") from exc
    if not isinstance(data, dict) or not data.get("zone") or not data.get("zone_id"):
        raise CloudflareError("Cloudflare metadata is incomplete")
    return data


def _api_request(
    token: str,
    method: str,
    path: str,
    *,
    query: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    url = f"{API_BASE}{path}"
    if query:
        url = f"{url}?{urlencode(query)}"
    payload = json.dumps(body).encode("utf-8") if body is not None else None
    request = Request(
        url,
        data=payload,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "yun-cloudflare/1",
        },
    )
    try:
        with urlopen(request, timeout=20) as response:
            result = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        try:
            result = json.loads(exc.read().decode("utf-8"))
            messages = []
            for item in result.get("errors", []):
                code = item.get("code")
                message = str(item.get("message", "API error"))
                messages.append(f"[{code}] {message}" if code is not None else message)
        except (json.JSONDecodeError, AttributeError):
            messages = [f"HTTP {exc.code}"]
        raise CloudflareError(
            f"Cloudflare API {method} {path} rejected the request: " + "; ".join(messages)
        ) from None
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise CloudflareError(f"Cloudflare API request failed: {type(exc).__name__}") from None
    if not isinstance(result, dict) or result.get("success") is not True:
        messages = []
        for item in result.get("errors", []):
            code = item.get("code")
            message = str(item.get("message", "API error"))
            messages.append(f"[{code}] {message}" if code is not None else message)
        raise CloudflareError(
            f"Cloudflare API {method} {path} failed: " + "; ".join(messages)
        )
    return result


def _normalize_account_id(value: str) -> str:
    account_id = value.strip()
    if len(account_id) != 32:
        raise CloudflareError(
            "Cloudflare Account ID must be exactly 32 characters; "
            f"received length={len(account_id)}"
        )
    if not account_id.isascii() or not account_id.isprintable() or any(
        character.isspace() for character in account_id
    ):
        raise CloudflareError(
            "Cloudflare Account ID contains unsupported whitespace or control characters"
        )
    return account_id


def _verify_access(
    token: str,
    zone: str,
    *,
    account_id: str | None = None,
) -> dict[str, str]:
    requested_account_id = _normalize_account_id(account_id) if account_id else None
    verification: dict[str, Any] | None = None
    token_type: str | None = None
    user_verify_error: CloudflareError | None = None

    if requested_account_id:
        verification = _api_request(
            token,
            "GET",
            f"/accounts/{quote(requested_account_id, safe='')}/tokens/verify",
        )
        token_type = "account"
    else:
        try:
            verification = _api_request(token, "GET", "/user/tokens/verify")
            token_type = "user"
        except CloudflareError as exc:
            user_verify_error = exc

    if verification is not None:
        token_result = verification.get("result") or {}
        if token_result.get("status") != "active":
            raise CloudflareError(
                f"Cloudflare token is {token_result.get('status', 'not active')}"
            )

    zones = _api_request(
        token,
        "GET",
        "/zones",
        query={"name": zone, "status": "active", "per_page": 5},
    ).get("result") or []
    matches = [item for item in zones if item.get("name") == zone and item.get("status") == "active"]
    if len(matches) != 1:
        raise CloudflareError(f"Expected one active Cloudflare zone named {zone}; found {len(matches)}")
    selected_zone = matches[0]
    zone_id = str(selected_zone["id"])
    account = selected_zone.get("account") or {}
    discovered_account_id = str(account.get("id") or "")
    if requested_account_id and discovered_account_id != requested_account_id:
        raise CloudflareError(
            "The requested Cloudflare Account ID does not own the selected zone"
        )

    if token_type is None:
        try:
            discovered_account_id = _normalize_account_id(discovered_account_id)
        except CloudflareError:
            raise CloudflareError(
                "Token can access the zone, but its account ID was not returned; "
                "cannot verify it as an Account API Token"
            ) from user_verify_error
        try:
            verification = _api_request(
                token,
                "GET",
                f"/accounts/{quote(discovered_account_id, safe='')}/tokens/verify",
            )
            token_type = "account"
        except CloudflareError as account_verify_error:
            raise CloudflareError(
                "Token can access the zone, but neither the User nor Account "
                "token verification endpoint accepted it"
            ) from account_verify_error
        token_result = verification.get("result") or {}
        if token_result.get("status") != "active":
            raise CloudflareError(
                f"Cloudflare token is {token_result.get('status', 'not active')}"
            )
    try:
        _api_request(
            token,
            "GET",
            f"/zones/{zone_id}/dns_records",
            query={"per_page": 1},
        )
    except CloudflareError as exc:
        raise CloudflareError(
            "dns_access=denied: the token and Account ID are valid and the zone "
            f"was found, but the token cannot read DNS records. Grant DNS Write "
            f"(or DNS Read for inspection only) and scope it to {zone}. "
            f"Cloudflare detail: {exc}"
        ) from exc
    return {
        "zone": zone,
        "zone_id": zone_id,
        "account_id": requested_account_id or discovered_account_id,
        "token_status": "active",
        "token_type": str(token_type),
    }


def _normalize_zone(value: str) -> str:
    zone = value.strip().lower().rstrip(".")
    if not DNS_NAME_RE.fullmatch(zone):
        raise CloudflareError("Zone must be a valid DNS name")
    return zone


def _normalize_record_name(value: str, zone: str) -> str:
    name = value.strip().lower().rstrip(".")
    if not DNS_NAME_RE.fullmatch(name):
        raise CloudflareError("Record name must be a valid fully-qualified DNS name")
    if name != zone and not name.endswith(f".{zone}"):
        raise CloudflareError(f"Record must be inside the configured zone {zone}")
    return name


def _normalize_content(record_type: str, value: str) -> str:
    content = value.strip().lower().rstrip(".")
    if record_type in {"A", "AAAA"}:
        address = ipaddress.ip_address(content)
        if (record_type == "A") != (address.version == 4):
            raise CloudflareError(f"{record_type} content has the wrong IP version")
        return str(address)
    if record_type == "CNAME" and DNS_NAME_RE.fullmatch(content):
        return content
    raise CloudflareError(f"Unsupported or invalid {record_type} record content")


def _policy_covers_zone(
    resources: Any,
    *,
    account_id: str,
    zone_id: str,
) -> bool:
    if not isinstance(resources, dict):
        return False
    exact_zone = f"com.cloudflare.api.account.zone.{zone_id}"
    if exact_zone in resources or "com.cloudflare.api.account.zone.*" in resources:
        return True
    account_resource = resources.get(f"com.cloudflare.api.account.{account_id}")
    return isinstance(account_resource, dict) and (
        "com.cloudflare.api.account.zone.*" in account_resource
        or exact_zone in account_resource
    )


def _summarize_token_policy(
    details: dict[str, Any],
    *,
    account_id: str,
    zone_id: str,
) -> dict[str, str]:
    dns_permission_present = False
    dns_allow_covers_zone = False
    dns_deny_covers_zone = False
    for policy in details.get("policies") or []:
        if not isinstance(policy, dict):
            continue
        permission_names = {
            str(group.get("name") or "").strip().lower()
            for group in policy.get("permission_groups") or []
            if isinstance(group, dict)
        }
        has_dns_permission = bool(
            permission_names.intersection({"dns read", "dns write", "dns edit"})
        )
        if not has_dns_permission:
            continue
        dns_permission_present = True
        if not _policy_covers_zone(
            policy.get("resources"), account_id=account_id, zone_id=zone_id
        ):
            continue
        if str(policy.get("effect") or "").lower() == "deny":
            dns_deny_covers_zone = True
        elif str(policy.get("effect") or "").lower() == "allow":
            dns_allow_covers_zone = True

    condition = details.get("condition") or {}
    request_ip = {}
    if isinstance(condition, dict):
        request_ip = condition.get("request_ip") or condition.get("request.ip") or {}
    has_ip_filter = isinstance(request_ip, dict) and bool(
        request_ip.get("in") or request_ip.get("not_in")
    )
    has_ttl = bool(details.get("not_before") or details.get("expires_on"))
    return {
        "dns_permission_present": str(dns_permission_present).lower(),
        "dns_zone_scope": "match" if dns_allow_covers_zone else "missing",
        "dns_explicit_deny": "present" if dns_deny_covers_zone else "absent",
        "client_ip_filter": "present" if has_ip_filter else "absent",
        "ttl_restriction": "present" if has_ttl else "absent",
    }


def command_diagnose(args: argparse.Namespace) -> None:
    """Diagnose an Account API Token without storing it or changing DNS."""
    zone = _normalize_zone(args.zone)
    token = getpass.getpass("Cloudflare API Token (hidden): ").strip()
    if not token or any(character.isspace() for character in token):
        raise CloudflareError("Token is empty or contains whitespace")
    account_id = getattr(args, "account_id", None)
    if not account_id:
        account_id = input(
            "Cloudflare Account ID (paste the 32-character value from Account home): "
        ).strip()
    account_id = _normalize_account_id(account_id)

    verification = _api_request(
        token,
        "GET",
        f"/accounts/{quote(account_id, safe='')}/tokens/verify",
    ).get("result") or {}
    if verification.get("status") != "active":
        raise CloudflareError(
            f"Cloudflare token is {verification.get('status', 'not active')}"
        )
    token_id = str(verification.get("id") or "")

    zones = _api_request(
        token,
        "GET",
        "/zones",
        query={"name": zone, "status": "active", "per_page": 5},
    ).get("result") or []
    matches = [
        item
        for item in zones
        if item.get("name") == zone and item.get("status") == "active"
    ]
    if len(matches) != 1:
        raise CloudflareError(
            f"Expected one active Cloudflare zone named {zone}; found {len(matches)}"
        )
    selected_zone = matches[0]
    zone_id = str(selected_zone.get("id") or "")
    discovered_account_id = str((selected_zone.get("account") or {}).get("id") or "")
    if discovered_account_id != account_id:
        raise CloudflareError(
            "The requested Cloudflare Account ID does not own the selected zone"
        )

    dns_access = "ok"
    try:
        _api_request(
            token,
            "GET",
            f"/zones/{zone_id}/dns_records",
            query={"per_page": 1},
        )
    except CloudflareError:
        dns_access = "denied"

    policy_summary: dict[str, str] | None = None
    if token_id:
        try:
            details = _api_request(
                token,
                "GET",
                f"/accounts/{quote(account_id, safe='')}/tokens/"
                f"{quote(token_id, safe='')}",
            ).get("result") or {}
            policy_summary = _summarize_token_policy(
                details,
                account_id=account_id,
                zone_id=zone_id,
            )
        except CloudflareError:
            policy_summary = None

    print("CLOUDFLARE_DIAGNOSTIC")
    print("token_status=active")
    print("zone_lookup=ok")
    print("zone_account_match=ok")
    print(f"dns_records_access={dns_access}")
    if policy_summary is None:
        print("policy_inspection=unavailable")
        diagnosis = "policy_details_unavailable" if dns_access == "denied" else "ok"
    else:
        print("policy_inspection=available")
        for field, value in policy_summary.items():
            print(f"{field}={value}")
        if dns_access == "ok":
            diagnosis = "ok"
        elif policy_summary["dns_explicit_deny"] == "present":
            diagnosis = "explicit_deny"
        elif policy_summary["dns_permission_present"] == "false":
            diagnosis = "dns_permission_missing"
        elif policy_summary["dns_zone_scope"] == "missing":
            diagnosis = "permission_resource_mismatch"
        else:
            diagnosis = "cloudflare_rejected_matching_policy"
    print(f"diagnosis={diagnosis}")


def command_configure(args: argparse.Namespace) -> None:
    zone = _normalize_zone(args.zone)
    token = getpass.getpass("Cloudflare API Token (hidden): ").strip()
    if not token or any(character.isspace() for character in token):
        raise CloudflareError("Token is empty or contains whitespace")
    account_id = getattr(args, "account_id", None)
    if token.startswith("cfat_") and not account_id:
        account_id = input(
            "Cloudflare Account ID (paste the 32-character value from Account home): "
        ).strip()
    access = _verify_access(token, zone, account_id=account_id)
    secret_path = _secret_path()
    metadata_path = _metadata_path()
    _atomic_write(secret_path, _protect_token(token))
    metadata = {
        "schema": 1,
        "zone": access["zone"],
        "zone_id": access["zone_id"],
        "account_id": access["account_id"],
        "token_type": access["token_type"],
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "secret_storage": "windows-dpapi-current-user" if os.name == "nt" else "mode-0600-file",
    }
    _atomic_write(metadata_path, (json.dumps(metadata, indent=2) + "\n").encode("utf-8"))
    print("CLOUDFLARE_CONFIGURED")
    print(f"zone={zone}")
    print(f"token_type={metadata['token_type']}")
    print(f"secret_storage={metadata['secret_storage']}")


def command_status(args: argparse.Namespace) -> None:
    secret = _secret_path()
    metadata_file = _metadata_path()
    print(f"token_configured={str(secret.is_file()).lower()}")
    print(f"metadata_configured={str(metadata_file.is_file()).lower()}")
    if metadata_file.is_file():
        metadata = _load_metadata()
        print(f"zone={metadata['zone']}")
        print(f"secret_storage={metadata.get('secret_storage', 'unknown')}")


def command_verify(args: argparse.Namespace) -> None:
    metadata = _load_metadata()
    access = _verify_access(
        _load_token(),
        metadata["zone"],
        account_id=metadata.get("account_id") if metadata.get("token_type") == "account" else None,
    )
    if access["zone_id"] != metadata["zone_id"]:
        raise CloudflareError("Configured Cloudflare zone ID no longer matches")
    print("CLOUDFLARE_VERIFY_OK")
    print(f"zone={access['zone']}")
    print(f"token_type={access['token_type']}")
    print("token_status=active")
    print("dns_access=ok")


def _record_summary(record: dict[str, Any]) -> str:
    fields = {
        "name": record.get("name"),
        "type": record.get("type"),
        "content": record.get("content"),
        "proxied": record.get("proxied"),
        "ttl": record.get("ttl"),
    }
    return json.dumps(fields, ensure_ascii=False, sort_keys=True)


def command_dns_upsert(args: argparse.Namespace) -> None:
    metadata = _load_metadata()
    zone = str(metadata["zone"])
    name = _normalize_record_name(args.name, zone)
    record_type = args.type.upper()
    content = _normalize_content(record_type, args.content)
    proxied = args.proxied == "true"
    if args.ttl != 1 and not 60 <= args.ttl <= 86400:
        raise CloudflareError("TTL must be 1 (automatic) or between 60 and 86400 seconds")
    if args.confirm_name is not None and args.confirm_name.strip().lower().rstrip(".") != name:
        raise CloudflareError("--confirm-name must exactly match --name")
    token = _load_token()
    lookup = _api_request(
        token,
        "GET",
        f"/zones/{metadata['zone_id']}/dns_records",
        query={"name": name, "per_page": 100},
    ).get("result") or []
    conflicting = [item for item in lookup if item.get("type") != record_type]
    matches = [item for item in lookup if item.get("type") == record_type]
    if conflicting:
        raise CloudflareError(f"A different DNS record type already exists at {name}")
    if len(matches) > 1:
        raise CloudflareError(f"Multiple {record_type} records exist at {name}; refusing an ambiguous update")
    desired = {
        "type": record_type,
        "name": name,
        "content": content,
        "ttl": args.ttl,
        "proxied": proxied,
        "comment": args.comment,
    }
    existing = matches[0] if matches else None
    print("action=" + ("update" if existing else "create"))
    print("desired=" + _record_summary(desired))
    if not args.apply:
        print("applied=false")
        print("hint=repeat with --apply --confirm-name followed by the exact record name")
        return
    if args.confirm_name is None:
        raise CloudflareError("DNS writes require --confirm-name with the exact record name")
    if existing:
        same = all(existing.get(field) == desired.get(field) for field in ("type", "name", "content", "ttl", "proxied"))
        if same:
            print("applied=false")
            print("reason=already-matches")
            return
        response = _api_request(
            token,
            "PATCH",
            f"/zones/{metadata['zone_id']}/dns_records/{existing['id']}",
            body=desired,
        )
    else:
        response = _api_request(
            token,
            "POST",
            f"/zones/{metadata['zone_id']}/dns_records",
            body=desired,
        )
    print("applied=true")
    print("record=" + _record_summary(response.get("result") or desired))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Secure Cloudflare DNS adapter for yun")
    commands = parser.add_subparsers(dest="command", required=True)

    configure = commands.add_parser("configure", help="validate and securely store a token")
    configure.add_argument("--zone", required=True, help="one authorized DNS zone")
    configure.add_argument(
        "--account-id",
        help="optional 32-character Account ID; prompted for cfat_ Account API Tokens",
    )
    configure.set_defaults(func=command_configure)

    status = commands.add_parser("status", help="show non-secret configuration state")
    status.set_defaults(func=command_status)

    verify = commands.add_parser("verify", help="verify token and zone DNS access")
    verify.set_defaults(func=command_verify)

    diagnose = commands.add_parser(
        "diagnose",
        help="inspect Account Token permission/resource binding without storing it",
    )
    diagnose.add_argument("--zone", required=True, help="one authorized DNS zone")
    diagnose.add_argument(
        "--account-id",
        help="optional 32-character Account ID; prompted when omitted",
    )
    diagnose.set_defaults(func=command_diagnose)

    upsert = commands.add_parser("dns-upsert", help="plan or apply one bounded DNS record upsert")
    upsert.add_argument("--name", required=True, help="fully-qualified record name")
    upsert.add_argument("--type", required=True, choices=("A", "AAAA", "CNAME"))
    upsert.add_argument("--content", required=True)
    upsert.add_argument("--proxied", choices=("true", "false"), default="true")
    upsert.add_argument("--ttl", type=int, default=1)
    upsert.add_argument("--comment", default="Managed by yun")
    upsert.add_argument("--apply", action="store_true")
    upsert.add_argument("--confirm-name")
    upsert.set_defaults(func=command_dns_upsert)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        args.func(args)
        return 0
    except (CloudflareError, OSError, ValueError) as exc:
        print(f"error={exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
