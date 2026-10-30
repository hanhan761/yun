"""No real secrets, network calls, or persistent credentials in these tests."""
import contextlib
import io
import json
import os
import pathlib
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import yun_tianhe_password as session
import yun_tianhe_vault as vault

PROFILE = {"target": "tianhe-ln5", "username": "example_user", "host": "203.0.113.11", "port": 22,
           "host_key_type": "ssh-ed25519", "host_fingerprint": "SHA256:test-only"}


@unittest.skipUnless(os.name == "nt", "Windows DPAPI integration")
class VaultTests(unittest.TestCase):
    def test_roundtrip_and_wrong_context_and_tamper(self):
        secret = b"synthetic-test-only-not-a-real-password"
        blob = vault.dpapi(secret, vault.entropy(PROFILE))
        self.assertNotIn(secret, blob)
        self.assertEqual(vault.dpapi(blob, vault.entropy(PROFILE), decrypt=True), secret)
        changed = {**PROFILE, "host_fingerprint": "SHA256:changed"}
        with self.assertRaises(OSError):
            vault.dpapi(blob, vault.entropy(changed), decrypt=True)
        corrupt = blob[:-1] + bytes([blob[-1] ^ 1])
        with self.assertRaises(OSError):
            vault.dpapi(corrupt, vault.entropy(PROFILE), decrypt=True)

    def test_storage_and_explicit_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "private" / "example_user.dpapi"
            with patch.object(vault, "vault_path", return_value=path):
                vault.save(PROFILE, "example_user", "synthetic-only")
                self.assertNotIn(b"synthetic-only", path.read_bytes())
                self.assertEqual(vault.load(PROFILE), ("example_user", "synthetic-only"))
                with self.assertRaises(FileExistsError):
                    vault.save(PROFILE, "example_user", "replacement")
                self.assertEqual(vault.load(PROFILE)[1], "synthetic-only")
                vault.save(PROFILE, "example_user", "replacement", replace=True)
                self.assertEqual(vault.load(PROFILE)[1], "replacement")
                with self.assertRaises(OSError):
                    vault.load({**PROFILE, "port": 23})
                with self.assertRaises(ValueError):
                    vault.save(PROFILE, "other-account", "synthetic")


class SessionTests(unittest.TestCase):
    def run_mock_session(self, *, second_pin_fails=False, authentication_fails=False, extra_args=(), expected_timeout=None, timeout_failure=False):
        events = []
        mock_paramiko = MagicMock()
        transport = mock_paramiko.Transport.return_value
        transport.is_authenticated.return_value = True
        if authentication_fails:
            transport.auth_password.side_effect = ValueError("Authentication failed.")
        transport.auth_password.side_effect = (
            ValueError("Authentication timeout.") if timeout_failure else ValueError("Authentication failed.") if authentication_fails else
            lambda *args, **kw: (self.assertEqual(transport.auth_timeout, expected_timeout) if expected_timeout is not None else None, events.append("auth")))
        def pin(*args):
            events.append("pin")
            if second_pin_fails:
                raise ValueError("identity changed")
        def load(*args):
            events.append("decrypt")
            return "example_user", "synthetic-only"
        output = io.StringIO()
        with patch.dict("sys.modules", {"paramiko": mock_paramiko}), \
             patch.object(session, "load_profile", return_value=PROFILE), \
             patch.object(session.socket, "create_connection", return_value=MagicMock()), \
             patch.object(session, "check_host", side_effect=pin), \
             patch.object(vault, "load", side_effect=load), \
             patch("yun_tianhe_coordination.publish_success"), \
             patch("yun_tianhe_coordination.AuthenticationLock"), \
             patch.object(session, "run_read_only", return_value={"exit_code": 0}), \
             patch("sys.stdin", io.StringIO('{"action":"close"}\n')), \
             contextlib.redirect_stdout(output):
            code = session.main(["--profile", "mock-only", "--credentials-dpapi", *extra_args])
        self.assertNotIn("synthetic-only", output.getvalue())
        return code, events, transport.auth_password.call_count

    def test_wrong_account_is_never_sent_to_ssh(self):
        mock_paramiko = MagicMock()
        transport = mock_paramiko.Transport.return_value
        output = io.StringIO()
        with patch.dict("sys.modules", {"paramiko": mock_paramiko}), \
             patch.object(session, "load_profile", return_value=PROFILE), \
             patch.object(session.socket, "create_connection", return_value=MagicMock()), \
             patch.object(session, "check_host"), \
             patch.object(vault, "load", return_value=("another_user", "synthetic-only")), \
             patch("yun_tianhe_coordination.AuthenticationLock"), \
             contextlib.redirect_stdout(output):
            self.assertEqual(session.main(["--profile", "mock-only", "--credentials-dpapi"]), 2)
        transport.auth_password.assert_not_called()
        self.assertNotIn("synthetic-only", output.getvalue())

    def test_auth_timeout_never_retries(self):
        code, events, count = self.run_mock_session(timeout_failure=True, extra_args=("--auth-timeout", "60"))
        self.assertEqual(code, 2)
        self.assertEqual(count, 1)

    def test_explicit_auth_timeout(self):
        self.assertEqual(self.run_mock_session(extra_args=("--auth-timeout", "60"), expected_timeout=60), (0, ["pin", "decrypt", "auth"], 1))

    def test_decrypt_after_fresh_pin(self):
        self.assertEqual(self.run_mock_session(), (0, ["pin", "decrypt", "auth"], 1))

    def test_changed_pin_never_decrypts(self):
        self.assertEqual(self.run_mock_session(second_pin_fails=True), (2, ["pin"], 0))

    def test_rejection_never_retries(self):
        code, events, count = self.run_mock_session(authentication_fails=True)
        self.assertEqual(code, 2)
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
