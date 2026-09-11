from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import importlib.util
import io
import os
from pathlib import Path
import sys
import unittest
from unittest import mock
from urllib.error import HTTPError


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "yun_cloudflare.py"
SPEC = importlib.util.spec_from_file_location("yun_cloudflare_under_test", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CredentialTests(unittest.TestCase):
    def test_account_id_accepts_non_hex_cloudflare_identifier_characters(self) -> None:
        account_id = "Z" * 32
        self.assertEqual(MODULE._normalize_account_id(account_id), account_id)

    def test_account_id_length_error_reports_length_without_echoing_value(self) -> None:
        account_id = "private-looking-id"
        with self.assertRaisesRegex(
            MODULE.CloudflareError,
            rf"received length={len(account_id)}$",
        ) as raised:
            MODULE._normalize_account_id(account_id)
        self.assertNotIn(account_id, str(raised.exception))

    @unittest.skipUnless(os.name == "nt", "DPAPI is Windows-specific")
    def test_dpapi_round_trip_does_not_store_plaintext(self) -> None:
        token = "synthetic-cloudflare-token-for-testing-only"
        protected = MODULE._protect_token(token)
        self.assertNotIn(token.encode("utf-8"), protected)
        self.assertEqual(MODULE._unprotect_token(protected), token)

    def test_configure_validates_before_writing_and_never_prints_token(self) -> None:
        token = "synthetic-cloudflare-token-for-testing-only"
        writes = []
        output = io.StringIO()
        with (
            mock.patch.object(MODULE.getpass, "getpass", return_value=token),
            mock.patch.object(
                MODULE,
                "_verify_access",
                return_value={
                    "zone": "matterswarm.com",
                    "zone_id": "a" * 32,
                    "account_id": "b" * 32,
                    "token_status": "active",
                    "token_type": "user",
                },
            ) as verify,
            mock.patch.object(MODULE, "_protect_token", return_value=b"protected"),
            mock.patch.object(MODULE, "_atomic_write", side_effect=lambda *args: writes.append(args)),
            redirect_stdout(output),
        ):
            MODULE.command_configure(
                argparse.Namespace(zone="matterswarm.com", account_id=None)
            )
        verify.assert_called_once_with(token, "matterswarm.com", account_id=None)
        self.assertEqual(len(writes), 2)
        self.assertNotIn(token, output.getvalue())
        self.assertIn("CLOUDFLARE_CONFIGURED", output.getvalue())

    def test_account_token_falls_back_from_user_verify_to_account_verify(self) -> None:
        calls = []

        def fake_api(token, method, path, **kwargs):
            calls.append(path)
            if path == "/user/tokens/verify":
                raise MODULE.CloudflareError(
                    "Cloudflare API rejected the request: Invalid API Token"
                )
            if path == "/zones":
                return {
                    "success": True,
                    "result": [
                        {
                            "id": "z" * 32,
                            "name": "matterswarm.com",
                            "status": "active",
                            "account": {"id": "a" * 32},
                        }
                    ],
                }
            if path == f"/accounts/{'a' * 32}/tokens/verify":
                return {"success": True, "result": {"status": "active"}}
            if path == f"/zones/{'z' * 32}/dns_records":
                return {"success": True, "result": []}
            raise AssertionError(f"Unexpected API path: {path}")

        with mock.patch.object(MODULE, "_api_request", side_effect=fake_api):
            access = MODULE._verify_access("synthetic-account-token", "matterswarm.com")

        self.assertEqual(access["token_type"], "account")
        self.assertIn(f"/accounts/{'a' * 32}/tokens/verify", calls)

    def test_prefixed_account_token_prompts_for_account_id_when_argument_is_omitted(self) -> None:
        token = "cfat_synthetic-account-token-for-testing-only"
        account_id = "Z" * 32
        args = argparse.Namespace(zone="matterswarm.com", account_id=None)
        with (
            mock.patch.object(MODULE.getpass, "getpass", return_value=token),
            mock.patch("builtins.input", return_value=account_id) as prompt,
            mock.patch.object(
                MODULE,
                "_verify_access",
                return_value={
                    "zone": "matterswarm.com",
                    "zone_id": "z" * 32,
                    "account_id": account_id,
                    "token_status": "active",
                    "token_type": "account",
                },
            ) as verify,
            mock.patch.object(MODULE, "_protect_token", return_value=b"protected"),
            mock.patch.object(MODULE, "_atomic_write") as atomic_write,
        ):
            MODULE.command_configure(args)
        prompt.assert_called_once()
        verify.assert_called_once_with(token, "matterswarm.com", account_id=account_id)
        self.assertEqual(atomic_write.call_count, 2)

    def test_explicit_account_id_verifies_account_token_before_zone_lookup(self) -> None:
        calls = []
        account_id = "a" * 32
        zone_id = "z" * 32

        def fake_api(token, method, path, **kwargs):
            calls.append(path)
            if path == f"/accounts/{account_id}/tokens/verify":
                return {"success": True, "result": {"status": "active"}}
            if path == "/zones":
                return {
                    "success": True,
                    "result": [
                        {
                            "id": zone_id,
                            "name": "matterswarm.com",
                            "status": "active",
                            "account": {"id": account_id},
                        }
                    ],
                }
            if path == f"/zones/{zone_id}/dns_records":
                return {"success": True, "result": []}
            raise AssertionError(f"Unexpected API path: {path}")

        with mock.patch.object(MODULE, "_api_request", side_effect=fake_api):
            access = MODULE._verify_access(
                "cfat_synthetic-account-token",
                "matterswarm.com",
                account_id=account_id,
            )

        self.assertEqual(access["token_type"], "account")
        self.assertEqual(access["account_id"], account_id)
        self.assertEqual(calls[0], f"/accounts/{account_id}/tokens/verify")

    def test_dns_auth_error_names_the_missing_zone_permission(self) -> None:
        account_id = "a" * 32
        zone_id = "z" * 32

        def fake_api(token, method, path, **kwargs):
            if path == f"/accounts/{account_id}/tokens/verify":
                return {"success": True, "result": {"status": "active"}}
            if path == "/zones":
                return {
                    "success": True,
                    "result": [
                        {
                            "id": zone_id,
                            "name": "matterswarm.com",
                            "status": "active",
                            "account": {"id": account_id},
                        }
                    ],
                }
            if path == f"/zones/{zone_id}/dns_records":
                raise MODULE.CloudflareError(
                    "Cloudflare API GET /zones/redacted/dns_records rejected "
                    "the request: [10000] Authentication error"
                )
            raise AssertionError(f"Unexpected API path: {path}")

        with (
            mock.patch.object(MODULE, "_api_request", side_effect=fake_api),
            self.assertRaisesRegex(
                MODULE.CloudflareError,
                r"dns_access.*DNS Write.*matterswarm\.com",
            ),
        ):
            MODULE._verify_access(
                "cfat_synthetic-account-token",
                "matterswarm.com",
                account_id=account_id,
            )

    def test_api_error_reports_safe_stage_and_cloudflare_code(self) -> None:
        response = io.BytesIO(
            b'{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}'
        )
        http_error = HTTPError(
            "https://api.cloudflare.com/client/v4/zones",
            403,
            "Forbidden",
            hdrs=None,
            fp=response,
        )
        with (
            mock.patch.object(MODULE, "urlopen", side_effect=http_error),
            self.assertRaisesRegex(
                MODULE.CloudflareError,
                r"GET /zones.*\[10000\] Authentication error",
            ),
        ):
            MODULE._api_request("synthetic-token", "GET", "/zones")

    def test_diagnose_identifies_dns_permission_bound_to_wrong_resource(self) -> None:
        token = "cfat_synthetic-account-token-for-testing-only"
        account_id = "a" * 32
        zone_id = "z" * 32
        output = io.StringIO()

        def fake_api(received_token, method, path, **kwargs):
            self.assertEqual(received_token, token)
            if path == f"/accounts/{account_id}/tokens/verify":
                return {
                    "success": True,
                    "result": {"id": "t" * 32, "status": "active"},
                }
            if path == "/zones":
                return {
                    "success": True,
                    "result": [
                        {
                            "id": zone_id,
                            "name": "matterswarm.com",
                            "status": "active",
                            "account": {"id": account_id},
                        }
                    ],
                }
            if path == f"/zones/{zone_id}/dns_records":
                raise MODULE.CloudflareError("[10000] Authentication error")
            if path == f"/accounts/{account_id}/tokens/{'t' * 32}":
                return {
                    "success": True,
                    "result": {
                        "status": "active",
                        "policies": [
                            {
                                "effect": "allow",
                                "permission_groups": [{"name": "DNS Write"}],
                                "resources": {
                                    f"com.cloudflare.api.account.{account_id}": "*"
                                },
                            }
                        ],
                    },
                }
            raise AssertionError(f"Unexpected API path: {path}")

        with (
            mock.patch.object(MODULE.getpass, "getpass", return_value=token),
            mock.patch.object(MODULE, "_api_request", side_effect=fake_api),
            redirect_stdout(output),
        ):
            MODULE.command_diagnose(
                argparse.Namespace(zone="matterswarm.com", account_id=account_id)
            )

        diagnostic = output.getvalue()
        self.assertIn("dns_permission_present=true", diagnostic)
        self.assertIn("dns_zone_scope=missing", diagnostic)
        self.assertIn("diagnosis=permission_resource_mismatch", diagnostic)
        self.assertNotIn(token, diagnostic)

    def test_zone_scope_recognizes_exact_and_account_nested_resources(self) -> None:
        account_id = "a" * 32
        zone_id = "z" * 32
        exact = {f"com.cloudflare.api.account.zone.{zone_id}": "*"}
        nested = {
            f"com.cloudflare.api.account.{account_id}": {
                "com.cloudflare.api.account.zone.*": "*"
            }
        }
        account_only = {f"com.cloudflare.api.account.{account_id}": "*"}

        self.assertTrue(
            MODULE._policy_covers_zone(
                exact, account_id=account_id, zone_id=zone_id
            )
        )
        self.assertTrue(
            MODULE._policy_covers_zone(
                nested, account_id=account_id, zone_id=zone_id
            )
        )
        self.assertFalse(
            MODULE._policy_covers_zone(
                account_only, account_id=account_id, zone_id=zone_id
            )
        )

    def test_policy_summary_detects_explicit_dns_deny(self) -> None:
        account_id = "a" * 32
        zone_id = "z" * 32
        resource = {f"com.cloudflare.api.account.zone.{zone_id}": "*"}
        summary = MODULE._summarize_token_policy(
            {
                "policies": [
                    {
                        "effect": "allow",
                        "permission_groups": [{"name": "DNS Write"}],
                        "resources": resource,
                    },
                    {
                        "effect": "deny",
                        "permission_groups": [{"name": "DNS Read"}],
                        "resources": resource,
                    },
                ]
            },
            account_id=account_id,
            zone_id=zone_id,
        )
        self.assertEqual(summary["dns_zone_scope"], "match")
        self.assertEqual(summary["dns_explicit_deny"], "present")


class DnsSafetyTests(unittest.TestCase):
    def test_record_name_must_stay_inside_configured_zone(self) -> None:
        with self.assertRaisesRegex(MODULE.CloudflareError, "inside the configured zone"):
            MODULE._normalize_record_name("am.example.net", "matterswarm.com")

    def test_dns_upsert_is_plan_only_without_apply(self) -> None:
        args = argparse.Namespace(
            name="am.matterswarm.com",
            type="CNAME",
            content="a" * 32 + ".cfargotunnel.com",
            proxied="true",
            ttl=1,
            comment="Managed by yun",
            apply=False,
            confirm_name=None,
        )
        output = io.StringIO()
        with (
            mock.patch.object(
                MODULE,
                "_load_metadata",
                return_value={"zone": "matterswarm.com", "zone_id": "b" * 32},
            ),
            mock.patch.object(MODULE, "_load_token", return_value="synthetic-token"),
            mock.patch.object(MODULE, "_api_request", return_value={"success": True, "result": []}) as api,
            redirect_stdout(output),
        ):
            MODULE.command_dns_upsert(args)
        self.assertEqual(api.call_count, 1)
        self.assertEqual(api.call_args.args[1], "GET")
        self.assertIn("action=create", output.getvalue())
        self.assertIn("applied=false", output.getvalue())

    def test_dns_write_requires_exact_confirmation(self) -> None:
        args = argparse.Namespace(
            name="am.matterswarm.com",
            type="CNAME",
            content="a" * 32 + ".cfargotunnel.com",
            proxied="true",
            ttl=1,
            comment="Managed by yun",
            apply=True,
            confirm_name=None,
        )
        with (
            mock.patch.object(
                MODULE,
                "_load_metadata",
                return_value={"zone": "matterswarm.com", "zone_id": "b" * 32},
            ),
            mock.patch.object(MODULE, "_load_token", return_value="synthetic-token"),
            mock.patch.object(MODULE, "_api_request", return_value={"success": True, "result": []}),
            self.assertRaisesRegex(MODULE.CloudflareError, "--confirm-name"),
        ):
            MODULE.command_dns_upsert(args)


if __name__ == "__main__":
    unittest.main()
