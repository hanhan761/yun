"""Narrow Tianhe yhbatch adapter using yun's existing verified SSH transport."""
from __future__ import annotations

import argparse
import datetime
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys

import yunctl


def hidden_external(argv, *, capture=False, dry_run=False, display=None, input_text=None):
    command = [str(item) for item in argv]
    if os.name == "nt" and command[0] in {"ssh", "scp", "ssh-keygen"}:
        for root in (r"C:\Program Files\Git\usr\bin", r"C:\Program Files (x86)\Git\usr\bin"):
            candidate = pathlib.Path(root) / (command[0] + ".exe")
            if candidate.is_file():
                command[0] = str(candidate)
                break
    if dry_run:
        return subprocess.CompletedProcess(command, 0, "", "")
    try:
        result = subprocess.run(command, input=input_text, capture_output=True,
                                encoding="utf-8", errors="replace", check=False,
                                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                                timeout=90)
    except FileNotFoundError as exc:
        raise yunctl.YunError(f"Required command missing: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise yunctl.YunError("Transport timed out; a submitted job may exist. Check before retry.") from exc
    if not capture:
        print(yunctl.redact(result.stdout or ""), end="")
        print(yunctl.redact(result.stderr or ""), end="", file=sys.stderr)
    return result


PREFLIGHT = r"""
set -u
printf 'hostname='; hostname
printf 'user='; id -un
printf 'home_disk='; df -h "$HOME" | tail -n 1
for tool in yhbatch yhrun yhqueue squeue sacct sinfo module python python3 vasp_std; do
  printf '%s=' "$tool"; command -v "$tool" || true
done
if command -v module >/dev/null 2>&1; then module list 2>&1; module avail vasp 2>&1; fi
""".strip()

QUEUE = r"""
set -u
if command -v yhqueue >/dev/null 2>&1; then yhqueue -u "$(id -un)"
elif command -v squeue >/dev/null 2>&1; then squeue -u "$(id -un)"
else printf 'No verified queue command available\n' >&2; exit 3; fi
""".strip()


def checked_target(name):
    target = yunctl.verify_target(name)
    yunctl.require_role(target, "server")
    if target.get("platform", "linux") != "linux":
        raise yunctl.YunError("Tianhe adapter requires the verified Linux login node.")
    return target


def submit_command(directory, script, digest):
    path = pathlib.PurePosixPath(directory)
    if not path.is_absolute() or ".." in path.parts or str(path) == "/" or any(c in directory for c in "\n\r\0"):
        raise yunctl.YunError("Use a bounded absolute run directory.")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.sh", script):
        raise yunctl.YunError("Script must be one .sh filename inside the run directory.")
    if not re.fullmatch(r"[a-fA-F0-9]{64}", digest):
        raise yunctl.YunError("A verified script SHA256 is required.")
    return (f"cd {shlex.quote(directory)} && command -v yhbatch >/dev/null && "
            f"printf '%s\\n' {shlex.quote(digest.lower() + '  ' + script)} | sha256sum -c - && "
            f"yhbatch {shlex.quote(script)}")


def main(argv=None):
    yunctl.run_external = hidden_external  # Process-local adapter; no core files edited.
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] not in {"preflight", "queue", "submit-site"}:
        return yunctl.main(args)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    for name in ("preflight", "queue"):
        p = sub.add_parser(name)
        p.add_argument("target")
    p = sub.add_parser("submit-site")
    p.add_argument("target")
    p.add_argument("--remote-dir", required=True)
    p.add_argument("--script", required=True)
    p.add_argument("--sha256", required=True)
    p.add_argument("--execute", action="store_true")
    p.add_argument("--confirm-target")
    p.add_argument("--receipt")
    opts = parser.parse_args(args)
    try:
        if opts.action == "submit-site":
            command = submit_command(opts.remote_dir, opts.script, opts.sha256)
            if not opts.execute:
                print(json.dumps({"mode": "plan", "target": opts.target, "command": command}, ensure_ascii=False))
                return 0
            if opts.confirm_target != opts.target or not opts.receipt:
                raise yunctl.YunError("Execution requires exact --confirm-target and a new --receipt path.")
            receipt_path = pathlib.Path(opts.receipt).resolve()
            receipt_path.parent.mkdir(parents=True, exist_ok=True)
            # Reserve a receipt before transmission: transport failure is never retried automatically.
            with receipt_path.open("x", encoding="utf-8") as f:
                json.dump({"target": opts.target, "state": "pending_verification", "remote_dir": opts.remote_dir,
                           "script": opts.script, "script_sha256": opts.sha256.lower(),
                           "time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()}, f, indent=2)
            target = checked_target(opts.target)
            yunctl.require_protected_confirmation(opts.target, target, opts.confirm_target)
            result = yunctl.ssh_run(target, "bash -lc " + shlex.quote(command), capture=True)
            output = yunctl.redact((result.stdout or "") + (result.stderr or ""))
            matches = re.findall(r"(?:Submitted batch job\s+|Submitted job\s+)(\d+)", output)
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt.update({"transport_exit_code": result.returncode, "output": output,
                            "job_id": matches[-1] if len(matches) == 1 else None,
                            "state": "submitted" if result.returncode == 0 and len(matches) == 1 else "outcome_unknown"})
            receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding="utf-8")
            print(json.dumps(receipt, ensure_ascii=False))
            return 0 if receipt["state"] == "submitted" else 4
        target = checked_target(opts.target)
        command = PREFLIGHT if opts.action == "preflight" else QUEUE
        return yunctl.ssh_run(target, "bash -lc " + shlex.quote(command)).returncode
    except (yunctl.YunError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
