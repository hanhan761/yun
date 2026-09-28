#!/usr/bin/env python3
"""Initialize a local development folder backed by one registered Yun host."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile

import yunctl


CONFIG_NAME = ".yun-workspace.json"
GUIDE_NAME = "YUN_WORKSPACE.md"
MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_TOTAL_BYTES = 250 * 1024 * 1024
SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache",
    ".sync", "data", "datasets", "artifacts", "runs", "weights", "checkpoints",
    "cache", "downloads", "results", "secrets", ".ssh", ".yun",
}
SKIP_SUFFIXES = {".env", ".pem", ".key", ".pub", ".p12", ".pfx", ".kdbx", ".pt", ".pth", ".ckpt", ".safetensors", ".pyc", ".pyo"}
SKIP_FILENAMES = {"credentials.json", "secrets.json", "token.json", "id_rsa", "id_ed25519"}


def remote_root(value: str) -> str:
    if not isinstance(value, str) or not value.startswith("/") or value == "/":
        raise yunctl.YunError("remote root must be an absolute Linux path below /")
    if any(part in {"", ".", ".."} for part in value[1:].split("/")):
        raise yunctl.YunError("remote root must be normalized without empty or parent segments")
    if any(not all(char.isalnum() or char in "._-" for char in part) for part in value[1:].split("/")):
        raise yunctl.YunError("remote root path segments must contain only letters, digits, dot, underscore, or hyphen")
    if any(ord(char) < 32 for char in value):
        raise yunctl.YunError("remote root contains a control character")
    return str(PurePosixPath(value))


def project_path(value: str) -> Path:
    path = Path(value).expanduser()
    if path.is_symlink():
        raise yunctl.YunError("project folder must not be a symlink")
    resolved = path.resolve()
    if resolved == Path(resolved.anchor):
        raise yunctl.YunError("project folder cannot be a filesystem root")
    if path.exists() and not path.is_dir():
        raise yunctl.YunError("project path is not a directory")
    return resolved


def selected_target(name: str) -> dict:
    target = yunctl.verify_target(name)
    yunctl.require_role(target, "server")
    yunctl.require_role(target, "compute")
    if target.get("platform", "linux") != "linux":
        raise yunctl.YunError("workspace releases currently require a Linux target")
    return target


def require_confirmation(name: str, confirmation: str | None) -> None:
    if confirmation != name:
        raise yunctl.YunError(f"remote workspace write requires --confirm-target {name}")


def probe(name: str) -> None:
    if yunctl.main(["probe", name]) != 0:
        raise yunctl.YunError(f"probe failed for {name}")


def prepare_remote(target: dict, root: str) -> None:
    quoted = shlex.quote(root)
    script = f'''set -eu
root={quoted}
if [ -L "$root" ] || {{ [ -e "$root" ] && [ ! -d "$root" ]; }}; then
  echo 'remote workspace root is not a directory' >&2; exit 2
fi
mkdir -p "$root/data" "$root/runs" "$root/cache" "$root/envs" \
  "$root/workspace/incoming" "$root/workspace/releases" "$root/workspace/manifests"
test -d "$root/data" && test -d "$root/workspace/releases"
'''
    if yunctl.ssh_run(target, script).returncode != 0:
        raise yunctl.YunError("remote workspace preparation failed")


def config_for(name: str, root: str) -> dict:
    return {"schema_version": 1, "target": name, "remote_root": root}


def guide_for(config: dict) -> str:
    name = config["target"]
    root = config["remote_root"]
    return f"""# Yun 工作区

本机负责源码、配置、文档和轻量检查。已登记的 `{name}` 承接大文件存储与计算，远端根目录为 `{root}`。

- 大数据、权重、环境、缓存和训练输出放在远端 `data/`、`runs/`、`envs/`、`cache/`。本机已有大文件先逐项核对，再单独迁移；初始化不会移动或删除它们。
- 使用 yun Skill 的 `scripts/yun_workspace.py sync . --confirm-target {name}` 发布源码。发布产物在 `{root}/workspace/releases/`，每次都是新版本；`workspace/current` 指向最近一次成功发布。
- 作业应固定使用一次同步返回的实际 release 路径。通过 yun Skill 的 `scripts/yunctl.py submit {name} JOB_SCRIPT --confirm-target {name}` 提交；用 `status`、`logs`、`fetch` 完成闭环。把大结果显式写到 `{root}/runs/`，不要写到 Yun 作业元数据目录或本机。
- 项目配置在 `{CONFIG_NAME}`；目标连接资料只从 yun 登记表和已验证 PEM 取得。不要在项目中保存私钥或填充后的 `.env`。

已有项目的专用同步脚本、环境和任务约束仍以现有项目文件为准；使用本入口前先核对它们与本页是否冲突。
"""


def agent_note() -> str:
    return f"""# Project workspace

Read [{GUIDE_NAME}]({GUIDE_NAME}) and `{CONFIG_NAME}` before storage or compute work.
Keep local work to source, configuration, documentation, and light checks. Use the
registered Yun target for large files and compute. Do not move or delete local
data during initialization. Probe the target and pin a release before each job.
"""


def write_if_absent(path: Path, content: str) -> bool:
    if path.exists():
        if path.read_text(encoding="utf-8") != content:
            raise yunctl.YunError(f"existing file differs; inspect it manually: {path}")
        return False
    path.write_text(content, encoding="utf-8")
    return True


def initialize(args: argparse.Namespace) -> int:
    folder = project_path(args.path)
    root = remote_root(args.remote_root)
    target = selected_target(args.target)
    config = config_for(args.target, root)
    config_text = json.dumps(config, indent=2, ensure_ascii=False) + "\n"
    guide = guide_for(config)
    was_empty = not folder.exists() or not any(folder.iterdir())
    for name, content in ((CONFIG_NAME, config_text), (GUIDE_NAME, guide)):
        file = folder / name
        if file.exists() and file.read_text(encoding="utf-8") != content:
            raise yunctl.YunError(f"existing file differs; inspect it manually: {file}")
    if not was_empty:
        candidates = sorted(item.name for item in folder.iterdir() if item.is_dir() and item.name in SKIP_DIRS)
        if candidates:
            print("review existing local storage before separate migration: " + ", ".join(candidates))
    if args.dry_run:
        print(f"plan: folder={folder} mode={'empty' if was_empty else 'existing'} target={args.target} root={root}")
        return 0
    if not args.local_only:
        require_confirmation(args.target, args.confirm_target)
        probe(args.target)
        prepare_remote(target, root)
    folder.mkdir(parents=True, exist_ok=True)
    write_if_absent(folder / CONFIG_NAME, config_text)
    write_if_absent(folder / GUIDE_NAME, guide)
    if not (folder / "AGENTS.md").exists():
        write_if_absent(folder / "AGENTS.md", agent_note())
    if was_empty:
        write_if_absent(folder / ".gitignore", ".venv/\n__pycache__/\n.env\n.env.*\n!.env.example\ndata/\nruns/\nweights/\n*.pem\n")
    print(f"initialized: {folder} ({'empty' if was_empty else 'existing'})")
    if args.local_only:
        print("remote directories pending; run init again with --confirm-target to prepare them")
    if not was_empty and (folder / "AGENTS.md").exists():
        print("existing project rules preserved; review them against YUN_WORKSPACE.md")
    return 0


def load_config(folder: Path) -> dict:
    file = folder / CONFIG_NAME
    if not file.is_file():
        raise yunctl.YunError(f"workspace config is missing: {file}")
    data = json.loads(file.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) != {"schema_version", "target", "remote_root"} or data["schema_version"] != 1:
        raise yunctl.YunError("invalid workspace config")
    yunctl.validate_target_name(data["target"])
    remote_root(data["remote_root"])
    return data


def safe_source(relative: Path) -> bool:
    parts = relative.parts
    if any(part in SKIP_DIRS or part.startswith(".env") for part in parts[:-1]):
        return False
    name = parts[-1]
    if name.lower() in SKIP_FILENAMES or name == ".env" or (name.startswith(".env") and name != ".env.example"):
        return False
    if relative.suffix.lower() in SKIP_SUFFIXES or name.endswith("~"):
        return False
    return True


def source_files(folder: Path) -> list[Path]:
    git = subprocess.run(["git", "-C", str(folder), "rev-parse", "--show-toplevel"], capture_output=True, text=True) if shutil.which("git") else None
    if git is not None and git.returncode == 0 and Path(git.stdout.strip()).resolve() == folder:
        listing = subprocess.run(["git", "-C", str(folder), "ls-files", "--cached", "-z"], capture_output=True, check=True)
        candidates = [folder / os.fsdecode(raw) for raw in listing.stdout.split(b"\0") if raw]
    else:
        candidates = []
        for current, dirs, files in os.walk(folder, followlinks=False):
            dirs[:] = [name for name in dirs if name not in SKIP_DIRS and not name.startswith(".env")]
            candidates.extend(Path(current) / name for name in files)
    selected: list[Path] = []
    total = 0
    for file in sorted(candidates):
        relative = file.relative_to(folder)
        if not safe_source(relative):
            continue
        if file.is_symlink():
            raise yunctl.YunError(f"source symlink requires review: {relative}")
        if not file.exists():
            continue
        if not file.is_file():
            continue
        size = file.stat().st_size
        if size > MAX_FILE_BYTES:
            raise yunctl.YunError(f"source file exceeds 20 MiB: {relative}")
        total += size
        if total > MAX_TOTAL_BYTES:
            raise yunctl.YunError("source selection exceeds 250 MiB; use a project-specific bounded release")
        selected.append(file)
    if not selected:
        raise yunctl.YunError("no source files selected")
    return selected


def digest(file: Path) -> str:
    sha = hashlib.sha256()
    with file.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(block)
    return sha.hexdigest()


def build_archive(folder: Path, files: list[Path], destination: Path) -> str:
    entries = [{"path": file.relative_to(folder).as_posix(), "bytes": file.stat().st_size, "sha256": digest(file)} for file in files]
    manifest = json.dumps({"schema_version": 1, "files": entries}, ensure_ascii=False, sort_keys=True).encode("utf-8")
    with tarfile.open(destination, "w:gz") as archive:
        for file in files:
            archive.add(file, arcname="code/" + file.relative_to(folder).as_posix(), recursive=False)
        header = tarfile.TarInfo("manifest.json")
        header.size = len(manifest)
        archive.addfile(header, io.BytesIO(manifest))
    with tarfile.open(destination, "r:gz") as archive:
        for entry in entries:
            stream = archive.extractfile("code/" + entry["path"])
            if stream is None:
                raise yunctl.YunError(f"release archive is missing {entry['path']}")
            sha = hashlib.sha256()
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                sha.update(block)
            if sha.hexdigest() != entry["sha256"]:
                raise yunctl.YunError(f"source changed during archive creation: {entry['path']}")
    return digest(destination)


def install_remote(target: dict, root: str, archive: Path, release_id: str, archive_sha: str) -> None:
    workspace = f"{root}/workspace"
    incoming = f"{workspace}/incoming/{release_id}.tar.gz"
    result = yunctl.run_external(
        [*yunctl.scp_argv(target), str(archive), f"{yunctl.destination(target, scp=True)}:{incoming}"],
        display=f"scp <source-release> {yunctl.destination(target, scp=True)}:<workspace-incoming>",
    )
    if result.returncode != 0:
        raise yunctl.YunError("source upload failed")
    q = shlex.quote
    script = f'''set -eu
workspace={q(workspace)}
archive={q(incoming)}
release={q(f"{workspace}/releases/{release_id}")}
stage={q(f"{workspace}/incoming/{release_id}.stage")}
manifest={q(f"{workspace}/manifests/{release_id}.json")}
current="$workspace/current"
test ! -e "$release" && test ! -e "$stage" && test ! -e "$manifest"
test ! -e "$current" || test -L "$current"
printf '%s  %s\\n' {q(archive_sha)} "$archive" | sha256sum -c -
mkdir "$stage"
tar -xzf "$archive" -C "$stage" --no-same-owner --no-same-permissions
test -d "$stage/code" && test -f "$stage/manifest.json"
mv "$stage/code" "$release"
mv "$stage/manifest.json" "$manifest"
rmdir "$stage"
ln -s "$release" "$workspace/.current-{release_id}"
mv -Tf "$workspace/.current-{release_id}" "$current"
rm -- "$archive"
readlink -f "$current"
'''
    result = yunctl.ssh_run(target, script, capture=True)
    if result.returncode != 0:
        raise yunctl.YunError("remote release installation failed; inspect bounded incoming/stage paths")
    actual = (result.stdout or "").strip().splitlines()[-1]
    if actual != f"{workspace}/releases/{release_id}":
        raise yunctl.YunError("remote current release verification failed")
    print(f"release={actual}")


def sync(args: argparse.Namespace) -> int:
    folder = project_path(args.path)
    config = load_config(folder)
    name = config["target"]
    target = selected_target(name)
    files = source_files(folder)
    print(f"source files={len(files)} bytes={sum(file.stat().st_size for file in files)} target={name}")
    if args.dry_run:
        for file in files:
            print(file.relative_to(folder).as_posix())
        return 0
    require_confirmation(name, args.confirm_target)
    probe(name)
    prepare_remote(target, config["remote_root"])
    with tempfile.TemporaryDirectory(prefix="yun-workspace-") as scratch:
        archive = Path(scratch) / "code.tar.gz"
        archive_sha = build_archive(folder, files, archive)
        release_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + archive_sha[:12]
        install_remote(target, config["remote_root"], archive, release_id, archive_sha)
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Initialize and publish a Yun-backed development workspace")
    commands = result.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="prepare a local project folder and remote storage layout")
    init.add_argument("path")
    init.add_argument("--target", required=True, help="registered Linux server+compute target")
    init.add_argument("--remote-root", required=True, help="absolute remote project directory")
    init.add_argument("--confirm-target")
    init.add_argument("--local-only", action="store_true")
    init.add_argument("--dry-run", action="store_true")
    init.set_defaults(func=initialize)
    publish = commands.add_parser("sync", help="publish bounded source as a new immutable release")
    publish.add_argument("path")
    publish.add_argument("--confirm-target")
    publish.add_argument("--dry-run", action="store_true")
    publish.set_defaults(func=sync)
    return result


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        return int(args.func(args))
    except (yunctl.YunError, OSError, json.JSONDecodeError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
