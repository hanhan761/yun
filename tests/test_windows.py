from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_yunctl import MODULE as yun, target, synthetic_host_material, FINGERPRINT


def windows_target(**kwargs):
    value = target(**kwargs)
    value.update(platform="windows", user="13081")
    return value


class WindowsContractTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("ssh-keygen"), "OpenSSH client required")
    def test_windows_pem_import_into_isolated_registry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertEqual(yun.main(["keygen", "win", "--directory", str(root)]), 0)
            pem = root / "yun_win.pem"
            known_hosts = root / "host.known_hosts"
            line, fingerprint = synthetic_host_material()
            known_hosts.write_text(line + "\n", encoding="utf-8")
            value = windows_target(protected=True)
            value.update(identity_file=str(pem), known_hosts_file=str(known_hosts), expected_host_key_sha256=fingerprint)
            source = root / "source.json"
            source.write_text(json.dumps({"schema_version": 1, "targets": {"win": value}}), encoding="utf-8")
            with mock.patch.dict(os.environ, {yun.REGISTRY_ENV: str(source)}):
                self.assertEqual(yun.main(["bundle-pem", "win", "--confirm-target", "win"]), 0)
            with mock.patch.dict(os.environ, {yun.REGISTRY_ENV: str(root / "imported" / "targets.json")}):
                self.assertEqual(yun.main(["import-pem", str(pem)]), 0)
                self.assertEqual(yun.main(["import-pem", str(pem)]), 0)
                self.assertEqual(yun.verify_target("win")["platform"], "windows")
    def test_platform_user_and_compute_validation(self):
        for user in ("13081", "yun-admin", "contoso\\alice"):
            value = windows_target()
            value["user"] = user
            self.assertEqual(yun.validate_target("win", value), value)
        for user in ("a@host", "-oProxyCommand=x", "user\nname"):
            value = windows_target()
            value["user"] = user
            with self.assertRaises(yun.YunError):
                yun.validate_target("win", value)
        with self.assertRaisesRegex(yun.YunError, "compute requires Linux"):
            yun.validate_target("win", windows_target(roles=["compute"]))
        value = windows_target()
        value["platform"] = "unknown"
        with self.assertRaisesRegex(yun.YunError, "platform"):
            yun.validate_target("win", value)
        self.assertEqual(yun.validate_target("old", target()), target())

    def test_bundle_round_trip_preserves_platform_and_legacy_shape(self):
        host_line, fingerprint = synthetic_host_material()
        for value in (target(), windows_target()):
            value["expected_host_key_sha256"] = fingerprint
            with mock.patch.object(yun, "resolved_connection_files", return_value=(Path(value["identity_file"]), Path(value["known_hosts_file"]))), mock.patch.object(yun, "verified_host_key_line", return_value=host_line), mock.patch.object(yun, "client_public_fingerprint", return_value=FINGERPRINT):
                payload = yun.build_bundle_payload("worker-one", value)
                _, restored, _ = yun.validate_bundle_payload(payload, Path(value["identity_file"]))
            self.assertEqual(restored.get("platform", "linux"), value.get("platform", "linux"))
            self.assertEqual("platform" in restored, "platform" in value)

    def test_register_windows_then_read_registry(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(os.environ, {yun.REGISTRY_ENV: str(Path(temporary) / "targets.json")}), mock.patch.object(yun, "restrict_local_file"), mock.patch.object(yun, "verify_target_payload", side_effect=lambda name, value: value):
            self.assertEqual(yun.main(["init"]), 0)
            self.assertEqual(yun.main(["register", "win", "--host", "host.example.invalid", "--user", "13081", "--platform", "windows", "--host-fingerprint", FINGERPRINT, "--role", "server"]), 0)
            self.assertEqual(yun.get_target("win")["platform"], "windows")

    def test_windows_exec_requires_confirmation_before_launch(self):
        with mock.patch.object(yun, "verify_target", return_value=windows_target(protected=True)), mock.patch.object(yun, "ssh_run") as run:
            with self.assertRaisesRegex(yun.YunError, "confirm-target"):
                yun.cmd_exec(argparse.Namespace(target="win", write=True, confirm_target=None, remote_command=["whoami.exe"], dry_run=False))
            run.assert_not_called()
            with self.assertRaisesRegex(yun.YunError, "confirm-target"):
                yun.cmd_exec_script(argparse.Namespace(target="win", write=True, confirm_target=None, script="x.ps1", dry_run=False))
            run.assert_not_called()

    def test_transfer_uses_pinned_sftp_and_one_quoted_file(self):
        value = windows_target(protected=True)
        files = (Path(value["identity_file"]), Path(value["known_hosts_file"]))
        with tempfile.TemporaryDirectory() as temporary:
            local = Path(temporary) / "some 中文 file.txt"
            with mock.patch.object(yun, "resolved_connection_files", return_value=files), mock.patch.object(yun, "run_external", return_value=subprocess.CompletedProcess([], 0)) as run:
                self.assertEqual(yun.windows_transfer(value, local, r"C:\Users\13081\some 中文 file.txt", upload=True, dry_run=True), 0)
            argv = run.call_args.args[0]
            self.assertEqual(argv[0], "sftp")
            self.assertIn("StrictHostKeyChecking=yes", argv)
            self.assertIn("IdentityAgent=none", argv)
            batch = run.call_args.kwargs["input_text"]
            self.assertEqual(batch.count("\n"), 2)
            self.assertIn('"/C:/Users/13081/some 中文 file.txt"', batch)
            for invalid in ("C:relative.txt", "C:/../file", "C:/x\nrm *", "C:/x*", "C:/dir/", "C:/x:stream", "C:/x[1]"):
                with self.subTest(path=invalid), self.assertRaises(yun.YunError):
                    yun.windows_transfer(value, local, invalid, upload=False, dry_run=True)

    def test_command_length_fails_before_network(self):
        with self.assertRaisesRegex(yun.YunError, "too long"):
            yun.powershell_command("x" * 5000)

    def test_linux_exec_stays_posix(self):
        with mock.patch.object(yun, "verify_target", return_value=target()), mock.patch.object(yun, "ssh_run", return_value=subprocess.CompletedProcess([], 0)) as run:
            yun.cmd_exec(argparse.Namespace(target="linux", write=False, remote_command=["printf", "%s", "hello world"], dry_run=False))
        self.assertEqual(run.call_args.args[1], "printf %s 'hello world'")


@unittest.skipUnless(os.name == "nt", "native Windows integration")
class WindowsExecutionTests(unittest.TestCase):
    @unittest.skipUnless(Path("C:/Windows/System32/OpenSSH/sftp-server.exe").is_file(), "local Windows SFTP server executable required")
    def test_real_sftp_upload_download_unicode_spaces_and_hash(self):
        # Exercise the actual Windows SFTP server over pipes; no listening service or firewall changes.
        with tempfile.TemporaryDirectory(prefix="yun-sftp-") as temporary:
            root = Path(temporary)
            source = root / "source 中文 file.bin"
            remote = root / "remote 中文 file.bin"
            fetched = root / "fetched 中文 file.bin"
            source.write_bytes(bytes(range(256)) * 8)
            value = windows_target()
            files = (Path(value["identity_file"]), Path(value["known_hosts_file"]))
            def local_sftp(argv, **kwargs):
                return subprocess.run(["sftp.exe", "-D", "C:/Windows/System32/OpenSSH/sftp-server.exe", "-b", "-"], input=kwargs["input_text"], capture_output=True, encoding="utf-8", timeout=20)
            with mock.patch.object(yun, "resolved_connection_files", return_value=files), mock.patch.object(yun, "run_external", side_effect=local_sftp):
                self.assertEqual(yun.windows_transfer(value, source, str(remote), upload=True, dry_run=False), 0)
                self.assertEqual(yun.windows_transfer(value, fetched, str(remote), upload=False, dry_run=False), 0)
            self.assertEqual(source.read_bytes(), fetched.read_bytes())

    def run_local(self, command):
        # The actual outer cmd.exe shell used by a default Windows OpenSSH server.
        return subprocess.run(["cmd.exe", "/d", "/s", "/c", command], capture_output=True, encoding="utf-8", errors="replace", timeout=30)

    def invoke_exec(self, argv):
        with mock.patch.object(yun, "verify_target", return_value=windows_target()), mock.patch.object(yun, "ssh_run", side_effect=lambda target, command, **kw: self.run_local(command)):
            return yun.cmd_exec(argparse.Namespace(target="win", write=False, remote_command=argv, dry_run=False))

    def test_real_probe_through_cmd_and_powershell_shells(self):
        with mock.patch.object(yun, "verify_target", return_value=windows_target()), mock.patch.object(yun, "ssh_run", return_value=subprocess.CompletedProcess([], 0)) as run:
            yun.cmd_probe(argparse.Namespace(target="win", dry_run=False))
        command = run.call_args.args[1]
        for result in (self.run_local(command), subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command], capture_output=True, encoding="utf-8", errors="replace", timeout=30)):
            self.assertEqual(result.returncode, 0, result.stderr)
            lines = result.stdout.strip().splitlines()
            self.assertEqual(lines[0], "YUN_PROBE_OK")
            data = json.loads(lines[1])
            self.assertEqual(data["platform"], "windows")
            self.assertGreater(data["memory"]["total_kib"], 0)
            self.assertGreater(data["root_disk"]["total_bytes"], 0)

    def test_native_argv_round_trip_special_characters(self):
        args = ["", "hello world", "中文", "O'Brien", 'a"b', "$(throw 'injected')", "& echo BAD", "C:\\path with space\\"]
        code = "import sys,json; assert sys.argv[1:] == json.loads(" + repr(json.dumps(args)) + "), repr(sys.argv[1:])"
        self.assertEqual(self.invoke_exec([sys.executable, "-c", code, *args]), 0)

    def test_native_exit_code_propagates(self):
        self.assertEqual(self.invoke_exec([sys.executable, "-c", "raise SystemExit(23)"]), 23)
        self.assertNotEqual(self.invoke_exec(["yun-nonexistent-executable.exe"]), 0)

    def test_script_cmdlet_parameters_and_error_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            script = Path(temporary) / "test.ps1"
            for source, code in (("Get-Service -Name ssh-agent | Select-Object -ExpandProperty Name", 0), ("throw 'expected failure'", 1), ("exit 19", 19), ("Get-Item -LiteralPath 'YUN-NONEXISTENT:/item'", 1)):
                script.write_text(source, encoding="utf-8")
                with mock.patch.object(yun, "verify_target", return_value=windows_target()), mock.patch.object(yun, "ssh_run", side_effect=lambda target, command, **kw: self.run_local(command)):
                    result = yun.cmd_exec_script(argparse.Namespace(target="win", script=str(script), write=False, dry_run=False))
                self.assertEqual(result, code)


if __name__ == "__main__":
    unittest.main()
