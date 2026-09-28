from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import yun_workspace as workspace


TARGET = {"platform": "linux", "roles": ["server", "compute"], "protected": True}


class WorkspaceTests(unittest.TestCase):
    def test_empty_folder_initializes_locally_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary) / "new-project"
            args = ["init", str(folder), "--target", "linux-new", "--remote-root", "/data/new-project", "--local-only"]
            with mock.patch.object(workspace, "selected_target", return_value=TARGET), mock.patch.object(workspace, "prepare_remote") as prepare:
                self.assertEqual(workspace.main(args), 0)
                self.assertEqual(workspace.main(args), 0)
            prepare.assert_not_called()
            self.assertEqual(json.loads((folder / workspace.CONFIG_NAME).read_text(encoding="utf-8")),
                             {"schema_version": 1, "target": "linux-new", "remote_root": "/data/new-project"})
            self.assertTrue((folder / "AGENTS.md").is_file())
            self.assertTrue((folder / ".gitignore").is_file())

    def test_existing_folder_preserves_project_files_and_detects_config_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / "AGENTS.md").write_text("Project rules\n", encoding="utf-8")
            (folder / ".gitignore").write_text("important-pattern\n", encoding="utf-8")
            (folder / "code.py").write_text("print('hello')\n", encoding="utf-8")
            (folder / "data").mkdir()
            (folder / "data" / "input.csv").write_text("keep me", encoding="utf-8")
            args = ["init", str(folder), "--target", "linux-new", "--remote-root", "/data/project", "--local-only"]
            with mock.patch.object(workspace, "selected_target", return_value=TARGET):
                self.assertEqual(workspace.main(args), 0)
                self.assertEqual(workspace.main(args[:-1] + ["--remote-root", "/data/other", "--local-only"]), 2)
            self.assertEqual((folder / "AGENTS.md").read_text(encoding="utf-8"), "Project rules\n")
            self.assertEqual((folder / ".gitignore").read_text(encoding="utf-8"), "important-pattern\n")
            self.assertEqual((folder / "code.py").read_text(encoding="utf-8"), "print('hello')\n")
            self.assertEqual((folder / "data" / "input.csv").read_text(encoding="utf-8"), "keep me")

    def test_remote_init_requires_exact_target_and_probes_before_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary) / "project"
            args = ["init", str(folder), "--target", "linux-new", "--remote-root", "/data/project"]
            with mock.patch.object(workspace, "selected_target", return_value=TARGET), mock.patch.object(workspace, "probe") as probe, mock.patch.object(workspace, "prepare_remote") as prepare:
                self.assertEqual(workspace.main(args), 2)
                self.assertFalse(folder.exists())
                self.assertEqual(workspace.main(args + ["--confirm-target", "linux-new"]), 0)
            probe.assert_called_once_with("linux-new")
            prepare.assert_called_once_with(TARGET, "/data/project")

    def test_source_selection_excludes_large_data_and_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / "code.py").write_text("pass\n", encoding="utf-8")
            (folder / ".env").write_text("SECRET=x", encoding="utf-8")
            (folder / ".workstation.env").write_text("WORKSTATION_HOST=private", encoding="utf-8")
            (folder / "id_rsa").write_text("PRIVATE", encoding="utf-8")
            (folder / "data").mkdir()
            (folder / "data" / "input.csv").write_text("large data", encoding="utf-8")
            self.assertEqual([file.name for file in workspace.source_files(folder)], ["code.py"])
            (folder / "big.py").write_bytes(b"x" * (workspace.MAX_FILE_BYTES + 1))
            with self.assertRaisesRegex(workspace.yunctl.YunError, "20 MiB"):
                workspace.source_files(folder)

    def test_archive_records_exact_source_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            source = folder / "code.py"
            source.write_text("value = 1\n", encoding="utf-8")
            archive = folder / "bundle.tar.gz"
            digest = workspace.build_archive(folder, [source], archive)
            self.assertEqual(digest, workspace.digest(archive))
            with tarfile.open(archive, "r:gz") as stream:
                self.assertEqual(stream.extractfile("code/code.py").read(), source.read_bytes())
                manifest = json.load(io.TextIOWrapper(stream.extractfile("manifest.json"), encoding="utf-8"))
            self.assertEqual(manifest["files"][0]["sha256"], workspace.digest(source))

    def test_remote_root_rejects_relative_root_and_parent_traversal(self) -> None:
        for value in ("relative", "/", "/data/../other", "/data//other", "/data/project/", "/data/with space", "/data/name;rm"):
            with self.subTest(value=value), self.assertRaises(workspace.yunctl.YunError):
                workspace.remote_root(value)

    def test_release_requires_remote_current_to_resolve_to_exact_new_version(self) -> None:
        release = "/data/project/workspace/releases/20260928T000000Z-abc123"
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(workspace.yunctl, "scp_argv", return_value=["scp"]), mock.patch.object(workspace.yunctl, "destination", return_value="user@host"), mock.patch.object(workspace.yunctl, "run_external", return_value=SimpleNamespace(returncode=0)), mock.patch.object(workspace.yunctl, "ssh_run", return_value=SimpleNamespace(returncode=0, stdout=release + "\n")):
            workspace.install_remote(TARGET, "/data/project", Path(temporary) / "archive.tar.gz", "20260928T000000Z-abc123", "a" * 64)
            with mock.patch.object(workspace.yunctl, "ssh_run", return_value=SimpleNamespace(returncode=0, stdout="/data/other/release\n")):
                with self.assertRaisesRegex(workspace.yunctl.YunError, "verification failed"):
                    workspace.install_remote(TARGET, "/data/project", Path(temporary) / "archive.tar.gz", "20260928T000000Z-abc123", "a" * 64)


if __name__ == "__main__":
    unittest.main()
