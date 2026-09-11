from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "yunctl.py"
SPEC = importlib.util.spec_from_file_location("yunctl_under_test", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


FINGERPRINT = "SHA256:" + "A" * 43
IDENTITY_FILE = str((Path(tempfile.gettempdir()) / "yun_worker-one.pem").resolve())
KNOWN_HOSTS_FILE = str((Path(tempfile.gettempdir()) / "yun_worker-one.known_hosts").resolve())


def target(*, protected: bool = False, roles: list[str] | None = None) -> dict:
    selected_roles = roles or ["server"]
    return {
        "description": "test target",
        "hostname": "host.example.invalid",
        "port": 22,
        "user": "yun-admin",
        "identity_file": IDENTITY_FILE,
        "known_hosts_file": KNOWN_HOSTS_FILE,
        "expected_host_key_sha256": FINGERPRINT,
        "roles": selected_roles,
        "protected": protected,
        "compute_backend": "tmux" if "compute" in selected_roles else None,
        "job_root": MODULE.JOB_ROOT if "compute" in selected_roles else None,
    }


def synthetic_host_material(host: str = "host.example.invalid") -> tuple[str, str]:
    key_bytes = b"synthetic-ed25519-host-key"
    encoded = base64.b64encode(key_bytes).decode("ascii")
    fingerprint = "SHA256:" + base64.b64encode(
        hashlib.sha256(key_bytes).digest()
    ).decode("ascii").rstrip("=")
    return f"{host} ssh-ed25519 {encoded}", fingerprint


class RegistryTests(unittest.TestCase):
    def test_registry_refuses_skill_internal_runtime_state(self) -> None:
        internal = MODULE.SKILL_ROOT / "targets.json"
        with mock.patch.dict(os.environ, {MODULE.REGISTRY_ENV: str(internal)}):
            with self.assertRaisesRegex(MODULE.YunError, "outside the installed skill"):
                MODULE.registry_path()

    def test_init_is_idempotent_and_registry_is_external(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config" / "targets.json"
            with mock.patch.dict(os.environ, {MODULE.REGISTRY_ENV: str(path)}), mock.patch.object(
                MODULE, "restrict_local_file"
            ):
                self.assertEqual(MODULE.main(["init"]), 0)
                self.assertEqual(MODULE.main(["init"]), 0)
                self.assertEqual(MODULE.load_registry(), {})
            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8")),
                {"schema_version": 1, "targets": {}},
            )

    def test_register_validates_then_writes_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "targets.json"
            path.write_text(
                json.dumps({"schema_version": 1, "targets": {}}), encoding="utf-8"
            )
            args = [
                "register",
                "worker-one",
                "--host",
                "host.example.invalid",
                "--user",
                "yun-admin",
                "--pem",
                IDENTITY_FILE,
                "--known-hosts",
                KNOWN_HOSTS_FILE,
                "--host-fingerprint",
                FINGERPRINT,
                "--role",
                "server",
                "--role",
                "compute",
            ]
            with mock.patch.dict(os.environ, {MODULE.REGISTRY_ENV: str(path)}), mock.patch.object(
                MODULE, "verify_target_payload", side_effect=lambda name, value: value
            ), mock.patch.object(MODULE, "restrict_local_file"):
                self.assertEqual(MODULE.main(args), 0)
                saved = MODULE.load_registry()["worker-one"]
            self.assertEqual(saved["roles"], ["server", "compute"])
            self.assertEqual(saved["compute_backend"], "tmux")
            self.assertEqual(saved["job_root"], ".yun/jobs")
            self.assertEqual(saved["identity_file"], IDENTITY_FILE)
            self.assertNotIn("ssh_alias", saved)

    def test_register_refuses_unconfirmed_replacement(self) -> None:
        payload = {"schema_version": 1, "targets": {"worker-one": target()}}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "targets.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            args = argparse.Namespace(
                name="worker-one",
                host="host.example.invalid",
                port=22,
                user="yun-admin",
                pem=IDENTITY_FILE,
                known_hosts=KNOWN_HOSTS_FILE,
                host_fingerprint=FINGERPRINT,
                role=["server"],
                description=None,
                protected=False,
                confirm_replace=None,
                dry_run=False,
            )
            with mock.patch.dict(os.environ, {MODULE.REGISTRY_ENV: str(path)}):
                with self.assertRaisesRegex(MODULE.YunError, "--confirm-replace worker-one"):
                    MODULE.cmd_register(args)

    def test_registry_rejects_unknown_target_fields(self) -> None:
        malformed = target()
        malformed["private_key"] = "must-not-be-stored"
        with self.assertRaisesRegex(MODULE.YunError, "unknown fields"):
            MODULE.validate_registry(
                {"schema_version": 1, "targets": {"worker-one": malformed}}
            )

    def test_registry_refuses_one_pem_shared_by_two_targets(self) -> None:
        with self.assertRaisesRegex(MODULE.YunError, "cannot share one PEM"):
            MODULE.validate_registry(
                {
                    "schema_version": 1,
                    "targets": {
                        "worker-one": target(),
                        "worker-two": target(),
                    },
                }
            )

    def test_registry_rejects_connection_and_description_injection(self) -> None:
        malformed_hosts = []
        for value in ("-oProxyCommand=bad", "admin@host.example", "[::1]", "bad host"):
            malformed = target()
            malformed["hostname"] = value
            malformed_hosts.append(malformed)
        malformed_user = target()
        malformed_user["user"] = "admin@host"
        malformed_identity = target()
        malformed_identity["identity_file"] = str(Path(tempfile.gettempdir()) / "not-pem.key")
        malformed_description = target()
        malformed_description["description"] = "line one\nline two"
        for malformed in (
            *malformed_hosts,
            malformed_user,
            malformed_identity,
            malformed_description,
        ):
            with self.subTest(malformed=malformed), self.assertRaises(MODULE.YunError):
                MODULE.validate_target("worker-one", malformed)


class IdentityTests(unittest.TestCase):
    def test_known_hosts_line_is_fingerprinted_without_emitting_key_data(self) -> None:
        key_bytes = b"synthetic-public-host-key"
        encoded = base64.b64encode(key_bytes).decode("ascii")
        expected = "SHA256:" + base64.b64encode(
            hashlib.sha256(key_bytes).digest()
        ).decode("ascii").rstrip("=")
        output = f"# Host found\nexample.invalid ssh-ed25519 {encoded}\n"
        self.assertEqual(MODULE.fingerprints_from_known_hosts(output), {expected})

    def test_verify_target_requires_exact_registered_identity_and_fingerprint(self) -> None:
        files = (Path(IDENTITY_FILE), Path(KNOWN_HOSTS_FILE))
        with mock.patch.object(MODULE, "resolved_connection_files", return_value=files), mock.patch.object(
            MODULE, "pinned_host_fingerprints", return_value={FINGERPRINT}
        ):
            self.assertEqual(MODULE.verify_target_payload("worker-one", target()), target())

        with mock.patch.object(MODULE, "resolved_connection_files", return_value=files), mock.patch.object(
            MODULE, "pinned_host_fingerprints", return_value=set()
        ):
            with self.assertRaisesRegex(MODULE.YunError, "fingerprint mismatch"):
                MODULE.verify_target_payload("worker-one", target())

    def test_connection_arguments_disable_ssh_config_and_pin_one_pem(self) -> None:
        files = (Path(IDENTITY_FILE), Path(KNOWN_HOSTS_FILE))
        with mock.patch.object(MODULE, "resolved_connection_files", return_value=files):
            options = MODULE.connection_options(target())
            ssh_target = MODULE.destination(target())
        self.assertEqual(options[:2], ["-F", "none"])
        self.assertIn("IdentitiesOnly=yes", options)
        self.assertIn("IdentityAgent=none", options)
        self.assertIn("StrictHostKeyChecking=yes", options)
        self.assertIn(f"UserKnownHostsFile={KNOWN_HOSTS_FILE}", options)
        self.assertEqual(options[options.index("-i") + 1], IDENTITY_FILE)
        self.assertEqual(ssh_target, "yun-admin@host.example.invalid")


class BundleTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("ssh-keygen"), "OpenSSH client is required")
    def test_bundle_then_import_rebuilds_empty_state_from_the_pem(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key_directory = root / "keys"
            self.assertEqual(
                MODULE.main(["keygen", "worker-one", "--directory", str(key_directory)]),
                0,
            )
            identity = key_directory / "yun_worker-one.pem"
            public_key = Path(f"{identity}.pub")
            known_hosts = root / "source.known_hosts"
            host_line, host_fingerprint = synthetic_host_material()
            known_hosts.write_text(host_line + "\n", encoding="utf-8")
            source_registry = root / "source" / "targets.json"
            source_registry.parent.mkdir()
            source_target = target(protected=True, roles=["server", "compute"])
            source_target["identity_file"] = str(identity.resolve())
            source_target["known_hosts_file"] = str(known_hosts.resolve())
            source_target["expected_host_key_sha256"] = host_fingerprint
            source_registry.write_text(
                json.dumps(
                    {"schema_version": 1, "targets": {"worker-one": source_target}}
                ),
                encoding="utf-8",
            )

            with mock.patch.dict(
                os.environ, {MODULE.REGISTRY_ENV: str(source_registry)}
            ):
                self.assertEqual(
                    MODULE.main(
                        [
                            "bundle-pem",
                            "worker-one",
                            "--confirm-target",
                            "worker-one",
                        ]
                    ),
                    0,
                )
                bundle = MODULE.read_bundle_payload(identity)
                self.assertEqual(bundle["name"], "worker-one")
                self.assertEqual(bundle["known_hosts_line"], host_line)

            public_key.unlink()
            known_hosts.unlink()
            import_registry = root / "imported" / "targets.json"
            with mock.patch.dict(
                os.environ, {MODULE.REGISTRY_ENV: str(import_registry)}
            ):
                self.assertEqual(MODULE.main(["import-pem", str(identity)]), 0)
                imported = MODULE.load_registry()["worker-one"]
                cache = Path(imported["known_hosts_file"])
                self.assertEqual(imported["identity_file"], str(identity.resolve()))
                self.assertEqual(cache.read_text(encoding="utf-8"), host_line + "\n")
                self.assertEqual(MODULE.main(["import-pem", str(identity)]), 0)

    def test_bundle_metadata_rejects_host_binding_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            identity = Path(temporary) / "yun_worker-one.pem"
            identity.touch()
            host_line, host_fingerprint = synthetic_host_material("other.example.invalid")
            payload = {
                "schema_version": MODULE.BUNDLE_SCHEMA_VERSION,
                "name": "worker-one",
                "connection": {
                    "description": "test target",
                    "hostname": "host.example.invalid",
                    "port": 22,
                    "user": "yun-admin",
                    "roles": ["server"],
                    "protected": False,
                },
                "known_hosts_line": host_line,
                "host_key_sha256": host_fingerprint,
                "client_key_sha256": FINGERPRINT,
            }
            registry = Path(temporary) / "runtime" / "targets.json"
            with mock.patch.dict(os.environ, {MODULE.REGISTRY_ENV: str(registry)}):
                with self.assertRaisesRegex(MODULE.YunError, "does not match target"):
                    MODULE.validate_bundle_payload(payload, identity)

    def test_bundle_metadata_rejects_unknown_fields(self) -> None:
        payload = {key: None for key in MODULE.BUNDLE_KEYS}
        payload["schema_version"] = MODULE.BUNDLE_SCHEMA_VERSION
        payload["unexpected"] = True
        with tempfile.TemporaryDirectory() as temporary:
            identity = Path(temporary) / "yun_worker-one.pem"
            identity.touch()
            with self.assertRaisesRegex(MODULE.YunError, "schema"):
                MODULE.validate_bundle_payload(payload, identity)

    def test_bundle_metadata_rejects_noncanonical_encoding(self) -> None:
        payload = {"schema_version": MODULE.BUNDLE_SCHEMA_VERSION}
        token = base64.urlsafe_b64encode(
            json.dumps(payload, indent=2).encode("utf-8")
        ).rstrip(b"=")
        with tempfile.TemporaryDirectory() as temporary:
            identity = Path(temporary) / "yun_worker-one.pem"
            identity.write_bytes(
                MODULE.BUNDLE_PREFIX
                + token
                + b"\n-----BEGIN RSA PRIVATE KEY-----\n"
            )
            with self.assertRaisesRegex(MODULE.YunError, "not canonical"):
                MODULE.read_bundle_payload(identity)

    def test_import_rejects_client_fingerprint_mismatch_before_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = root / "yun_worker-one.pem"
            host_line, host_fingerprint = synthetic_host_material()
            payload = {
                "schema_version": MODULE.BUNDLE_SCHEMA_VERSION,
                "name": "worker-one",
                "connection": {
                    "description": "test target",
                    "hostname": "host.example.invalid",
                    "port": 22,
                    "user": "yun-admin",
                    "roles": ["server"],
                    "protected": False,
                },
                "known_hosts_line": host_line,
                "host_key_sha256": host_fingerprint,
                "client_key_sha256": FINGERPRINT,
            }
            identity.write_bytes(MODULE.encode_bundle_payload(payload) + b"private-body")
            registry = root / "runtime" / "targets.json"
            with (
                mock.patch.dict(os.environ, {MODULE.REGISTRY_ENV: str(registry)}),
                mock.patch.object(MODULE, "restrict_local_file"),
                mock.patch.object(
                    MODULE, "client_public_fingerprint", return_value="SHA256:" + "B" * 43
                ),
            ):
                with self.assertRaisesRegex(MODULE.YunError, "client fingerprint"):
                    MODULE.cmd_import_pem(
                        argparse.Namespace(
                            pem=str(identity), dry_run=False, confirm_replace=None
                        )
                    )
            self.assertFalse(registry.exists())
            self.assertFalse((registry.parent / "known_hosts").exists())

    def test_import_requires_exact_confirmation_to_replace_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = root / "yun_worker-one.pem"
            host_line, host_fingerprint = synthetic_host_material()
            payload = {
                "schema_version": MODULE.BUNDLE_SCHEMA_VERSION,
                "name": "worker-one",
                "connection": {
                    "description": "test target",
                    "hostname": "host.example.invalid",
                    "port": 22,
                    "user": "yun-admin",
                    "roles": ["server"],
                    "protected": False,
                },
                "known_hosts_line": host_line,
                "host_key_sha256": host_fingerprint,
                "client_key_sha256": FINGERPRINT,
            }
            identity.write_bytes(MODULE.encode_bundle_payload(payload) + b"private-body")
            registry = root / "runtime" / "targets.json"
            cache = registry.parent / "known_hosts" / "worker-one.known_hosts"
            cache.parent.mkdir(parents=True)
            cache.write_text("stale\n", encoding="utf-8")
            with (
                mock.patch.dict(os.environ, {MODULE.REGISTRY_ENV: str(registry)}),
                mock.patch.object(MODULE, "restrict_local_file"),
                mock.patch.object(
                    MODULE, "client_public_fingerprint", return_value=FINGERPRINT
                ),
            ):
                with self.assertRaisesRegex(MODULE.YunError, "confirm-replace worker-one"):
                    MODULE.cmd_import_pem(
                        argparse.Namespace(
                            pem=str(identity), dry_run=False, confirm_replace=None
                        )
                    )
            self.assertEqual(cache.read_text(encoding="utf-8"), "stale\n")
            self.assertFalse(registry.exists())


class SafetyTests(unittest.TestCase):
    def test_protected_target_requires_exact_confirmation(self) -> None:
        protected = target(protected=True)
        with self.assertRaisesRegex(MODULE.YunError, "--confirm-target worker-one"):
            MODULE.require_protected_confirmation("worker-one", protected, None)
        MODULE.require_protected_confirmation("worker-one", protected, "worker-one")

    def test_job_ids_and_paths_cannot_escape_root(self) -> None:
        compute = target(roles=["compute"])
        self.assertEqual(
            MODULE.job_paths(compute, "job-123"),
            ("$HOME/.yun/jobs/job-123", "~/.yun/jobs/job-123"),
        )
        for invalid in ("../escape", "/absolute", "job name", ""):
            with self.subTest(invalid=invalid), self.assertRaises(MODULE.YunError):
                MODULE.validate_job_id(invalid)

    def test_redaction_covers_common_secret_shapes(self) -> None:
        text = (
            "Authorization: Bearer synthetic-bearer-value\n"
            "token=synthetic-token-value\n"
            "password: synthetic-password-value\n"
        )
        redacted = MODULE.redact(text)
        self.assertNotIn("synthetic-bearer-value", redacted)
        self.assertNotIn("synthetic-token-value", redacted)
        self.assertNotIn("synthetic-password-value", redacted)
        self.assertGreaterEqual(redacted.count("[REDACTED]"), 3)

    def test_keygen_dry_run_produces_one_rsa_pem_identity(self) -> None:
        args = argparse.Namespace(
            directory=tempfile.gettempdir(),
            name="worker-one",
            dry_run=True,
        )
        with mock.patch.object(MODULE, "run_external") as run:
            run.return_value.returncode = 0
            self.assertEqual(MODULE.cmd_keygen(args), 0)
        command = run.call_args.args[0]
        self.assertIn("rsa", command)
        self.assertIn("4096", command)
        self.assertIn("PEM", command)
        self.assertEqual(command[command.index("-N") + 1], "")
        self.assertIn(str(Path(tempfile.gettempdir()).resolve() / "yun_worker-one.pem"), command)

    @unittest.skipUnless(shutil.which("ssh-keygen"), "OpenSSH client is required")
    def test_rsa_pem_allows_a_yun_metadata_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            self.assertEqual(
                MODULE.main(["keygen", "prefix-probe", "--directory", temporary]),
                0,
            )
            private_key = Path(temporary) / "yun_prefix-probe.pem"
            candidate = Path(temporary) / "yun_prefix-probe-candidate.pem"
            before = subprocess.run(
                ["ssh-keygen", "-y", "-f", str(private_key)],
                check=True,
                capture_output=True,
            ).stdout
            candidate.write_bytes(b"# YUN-BUNDLE-V1 e30\n" + private_key.read_bytes())
            MODULE.restrict_local_file(candidate)
            after = subprocess.run(
                ["ssh-keygen", "-y", "-f", str(candidate)],
                check=True,
                capture_output=True,
            ).stdout
            self.assertEqual(after, before)

    def test_remote_paths_reject_option_and_control_injection(self) -> None:
        self.assertEqual(MODULE.valid_remote_path("/tmp/result.json"), "/tmp/result.json")
        for invalid in ("-rf", "line\nbreak", "nul\x00byte", ""):
            with self.subTest(invalid=invalid), self.assertRaises(MODULE.YunError):
                MODULE.valid_remote_path(invalid)


class PackageTests(unittest.TestCase):
    def test_skill_frontmatter_and_ui_metadata_match_yun(self) -> None:
        root = MODULE_PATH.parents[1]
        skill = (root / "SKILL.md").read_text(encoding="utf-8")
        metadata = (root / "agents" / "openai.yaml").read_text(encoding="utf-8")
        self.assertTrue(skill.startswith("---\nname: yun\n"))
        self.assertIn("/yun", skill)
        self.assertIn("$yun", skill)
        self.assertIn("import-pem", skill)
        self.assertIn("self-describing", skill)
        self.assertIn('display_name: "云"', metadata)
        self.assertIn("allow_implicit_invocation: true", metadata)

    def test_one_off_subdomain_prefers_manual_dashboard_cname_workflow(self) -> None:
        root = MODULE_PATH.parents[1]
        skill = (root / "SKILL.md").read_text(encoding="utf-8")
        cloudflare = (root / "references" / "cloudflare.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("one-off subdomain", skill)
        self.assertIn("manual dashboard CNAME", skill)
        for required in (
            "Preferred one-off subdomain workflow",
            "<TUNNEL-UUID>.cfargotunnel.com",
            "Tunnel ingress",
            "public DNS",
            "HTTPS",
            "API health",
            "rollback",
        ):
            self.assertIn(required, cloudflare)


if __name__ == "__main__":
    unittest.main()
