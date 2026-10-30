"""Password-only ln5 session: local dialog, private pipe, or authorized DPAPI.

Read-only JSON-line actions: preflight, queue, close. No job submission here.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pathlib
import re
import socket
import sys
import time

import yun_tianhe

TARGET = "tianhe-ln5"
def local_appdata():
    value = os.environ.get("LOCALAPPDATA")
    if value:
        return pathlib.Path(value)
    if os.name == "nt":
        import ctypes
        buffer = ctypes.create_unicode_buffer(32768)
        if ctypes.windll.shell32.SHGetFolderPathW(None, 0x001C, None, 0, buffer) != 0:
            raise OSError("Could not resolve the current user's LocalAppData.")
        return pathlib.Path(buffer.value)
    raise OSError("This scoped password dialog requires the Windows controller.")


DEPS = local_appdata() / "yun" / "tianhe-deps"


def fingerprint(key):
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def load_profile(path):
    profile = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    if profile.get("target") != TARGET:
        raise ValueError("Profile must select the confirmed Tianhe target.")
    host, port, username = profile.get("host"), profile.get("port"), profile.get("username")
    if not isinstance(host, str) or not host or len(host) > 253 or not re.fullmatch(r"[A-Za-z0-9.:-]+", host):
        raise ValueError("Profile requires a valid confirmed host.")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("Profile requires a valid SSH port.")
    if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", username):
        raise ValueError("Profile requires a valid confirmed SSH account.")
    if profile.get("trust_source") not in {"independent_fingerprint_confirmation", "explicit_user_first_trust"}:
        raise ValueError("Host trust has not been established.")
    if profile.get("host_key_type") != "ssh-ed25519" or not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}=?", profile.get("host_fingerprint", "")):
        raise ValueError("An ED25519 host fingerprint is required.")
    if not profile.get("trust_evidence"):
        raise ValueError("Record the actual user confirmation or independent evidence.")
    return profile


def check_host(profile, key):
    if key.get_name() != profile["host_key_type"] or fingerprint(key) != profile["host_fingerprint"]:
        raise ValueError("ln5 host identity changed; credentials were not requested or sent.")


def confirm_current_host(profile, key, profile_path):
    """An actual local user click, never an automatic replacement of the pin."""
    import datetime
    import tempfile
    import tkinter as tk
    from tkinter import messagebox

    current = fingerprint(key)
    if key.get_name() != "ssh-ed25519":
        raise ValueError("Unexpected host key type.")
    root = tk.Tk()
    root.withdraw()
    try:
        accepted = messagebox.askyesno(
            "yun ln5 首次连接确认",
            "目标：经 aTrust 接入的 TH-M / ln5（使用已确认的本机配置）\n\n"
            "当前服务器身份与旧记录不同，原因尚未确认。\n"
            f"当前：{current}\n旧记录：{profile['host_fingerprint']}\n\n"
            "是否信任这个指定节点的当前身份并继续密码登录？\n"
            "选择是仅更新此节点的记录；以后仍会检查变化。",
            parent=root, default="no")
    finally:
        root.destroy()
    if not accepted:
        raise ValueError("User declined the current host identity; no credentials sent.")
    updated = dict(profile)
    updated.setdefault("previous_host_fingerprints", []).append(profile["host_fingerprint"])
    updated.update(host_fingerprint=current, trust_source="explicit_user_first_trust",
                   trust_evidence="User clicked Yes in the local ln5 current-host confirmation dialog.",
                   trust_time_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
    destination = pathlib.Path(profile_path).resolve()
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=destination.parent,
                                     prefix="ln5-trust-", suffix=".tmp", delete=False) as stream:
        json.dump(updated, stream, ensure_ascii=False, indent=2)
        temporary = pathlib.Path(stream.name)
    os.replace(temporary, destination)
    return updated


def prompt_credentials():
    import tkinter as tk
    from tkinter import messagebox

    result = []
    root = tk.Tk()
    root.title("yun 天河 ln5 登录")
    root.resizable(False, False)
    root.lift()
    tk.Label(root, text="ln5（使用已确认的本机配置）\n输入当前 SSH 账号及密码；仅保留在本次进程内存中。", padx=20, pady=15).pack()
    tk.Label(root, text="SSH 账号").pack()
    user = tk.Entry(root, width=38)
    user.pack(padx=20, pady=5)
    tk.Label(root, text="SSH 密码").pack()
    password = tk.Entry(root, width=38, show="*")
    password.pack(padx=20, pady=5)

    def submit():
        if not user.get().strip() or not password.get():
            messagebox.showinfo("未填写完整", "请填写 SSH 账号和密码。", parent=root)
            return
        result.append((user.get().strip(), password.get()))
        password.delete(0, tk.END)
        root.destroy()

    tk.Button(root, text="登录一次并检查环境", command=submit).pack(pady=15)
    root.bind("<Return>", lambda event: submit())
    root.protocol("WM_DELETE_WINDOW", root.destroy)
    root.after(1200000, root.destroy)
    user.focus_set()
    root.mainloop()
    if not result:
        raise ValueError("Login cancelled; no credentials sent.")
    return result.pop()


def credentials_from_pipe():
    line = sys.stdin.readline(16385)
    if not line.endswith("\n") or len(line) > 16384:
        raise ValueError("Expected one bounded credential JSON line on the private stdin pipe.")
    data = json.loads(line)
    line = None
    if not isinstance(data, dict) or set(data) != {"username", "password"}:
        raise ValueError("Credential pipe requires username and password only.")
    username = data.pop("username")
    password = data.pop("password")
    if not isinstance(username, str) or not username.strip() or not isinstance(password, str) or not password:
        raise ValueError("Credential pipe fields must be nonempty strings.")
    return username.strip(), password


def emit(value):
    print(json.dumps(value, ensure_ascii=False), flush=True)


def run_read_only(client, action):
    import shlex

    commands = {"preflight": yun_tianhe.PREFLIGHT, "queue": yun_tianhe.QUEUE}
    if action not in commands:
        raise ValueError("Only preflight, queue and close are supported; no remote writes.")
    _, stdout, stderr = client.exec_command("bash -lc " + shlex.quote(commands[action]), timeout=30)
    output = stdout.read(262145)
    errors = stderr.read(65537)
    if len(output) > 262144 or len(errors) > 65536:
        raise ValueError("Diagnostic output exceeded the bounded limit.")
    return {"action": action, "exit_code": stdout.channel.recv_exit_status(),
            "stdout": yun_tianhe.yunctl.redact(output.decode("utf-8", "replace")),
            "stderr": yun_tianhe.yunctl.redact(errors.decode("utf-8", "replace"))}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--confirm-host-in-dialog", action="store_true",
                        help="Ask the local user to accept the current ln5 identity if the old pin differs.")
    credentials = parser.add_mutually_exclusive_group()
    credentials.add_argument("--credentials-stdin", action="store_true",
                        help="Read explicitly user-supplied credentials from a private stdin pipe, never argv.")
    credentials.add_argument("--credentials-dpapi", action="store_true",
                            help="Use the authorized current-Windows-user encrypted ln5 credential.")
    parser.add_argument("--auth-timeout", type=int, choices=range(15, 121), default=30, metavar="15..120",
                        help="Wait for one authentication response; does not enable retries.")
    parser.add_argument("--recovery-source", default="session", help="Non-secret observation source label.")
    opts = parser.parse_args(argv)
    auth_lock = None
    client = None
    transport = None
    sock = None
    phase = "profile_validation"
    phase_started = time.monotonic()
    timings = {}
    def mark(next_phase):
        nonlocal phase, phase_started
        now = time.monotonic()
        timings[phase] = round(now - phase_started, 3)
        phase, phase_started = next_phase, now
    try:
        # Fail closed before network or credential UI if no actual trust evidence exists.
        profile = load_profile(opts.profile)
        sys.path.insert(0, str(DEPS))
        import paramiko

        from yun_tianhe_coordination import AuthenticationLock
        mark("authentication_mutex")
        auth_lock = AuthenticationLock(profile)
        auth_lock.acquire()
        mark("ssh_handshake")
        sock = socket.create_connection((profile["host"], profile["port"]), timeout=10)
        transport = paramiko.Transport(sock)
        transport.get_security_options().key_types = ("ssh-ed25519",)
        transport.start_client(timeout=10)
        mark("host_pin_check")
        key = transport.get_remote_server_key()
        try:
            check_host(profile, key)
        except ValueError:
            if not opts.confirm_host_in_dialog:
                raise
            emit({"state": "waiting_for_local_host_confirmation", "target": TARGET})
            profile = confirm_current_host(profile, key, opts.profile)
            check_host(profile, key)
        emit({"state": "host_pin_matched", "target": TARGET,
              "next": "Windows CurrentUser DPAPI" if opts.credentials_dpapi else
                      "private credential pipe" if opts.credentials_stdin else "user-operated local SSH login dialog"})
        username, password = None, None
        if not opts.credentials_dpapi:
            # Human/pipe waiting must not consume the server LoginGraceTime.
            transport.close(); transport = None
            sock.close(); sock = None
            mark("credential_pipe" if opts.credentials_stdin else "user_login_dialog")
            username, password = credentials_from_pipe() if opts.credentials_stdin else prompt_credentials()
        try:
            if not opts.credentials_dpapi:
                mark("fresh_ssh_handshake")
                sock = socket.create_connection((profile["host"], profile["port"]), timeout=10)
                transport = paramiko.Transport(sock)
                transport.get_security_options().key_types = ("ssh-ed25519",)
                transport.start_client(timeout=10)
                check_host(profile, transport.get_remote_server_key())
            else:
                # The same freshly pinned transport is used for DPAPI authentication.
                mark("credential_dpapi")
                import yun_tianhe_vault
                username, password = yun_tianhe_vault.load(profile)
            if username != profile["username"]:
                raise ValueError("Credential account does not match the pinned profile.")
            mark("password_authentication")
            transport.auth_timeout = opts.auth_timeout
            # One password attempt, no key search, no agent, no OTP guessing or retry.
            transport.auth_password(username, password, fallback=False)
        finally:
            password = None
        if not transport.is_authenticated():
            raise ValueError("SSH authentication did not complete.")
        auth_lock.release()
        transport.set_keepalive(30)
        client = paramiko.SSHClient()
        client._transport = transport
        mark("read_only_diagnostics")
        emit({"state": "authenticated", "target": TARGET, "timings_seconds": dict(timings),
              "auth_timeout_seconds": opts.auth_timeout})
        preflight = run_read_only(client, "preflight")
        emit(preflight)
        if opts.credentials_dpapi and preflight.get("exit_code") == 0:
            try:
                from yun_tianhe_coordination import publish_success
                publish_success(profile, opts.recovery_source)
            except OSError:
                emit({"state": "recovery_signal_unavailable", "target": TARGET})
        # Parent keeps the same authenticated connection for subsequent read-only checks.
        for line in sys.stdin:
            request = json.loads(line)
            if request.get("action") == "close":
                break
            emit(run_read_only(client, request.get("action")))
        return 0
    except Exception as exc:
        # Never emit exception text that could contain credential or challenge data.
        safe_reason = {
            "No existing session": "ssh_session_expired_before_authentication",
            "Authentication timeout.": "authentication_timed_out",
            "Authentication failed.": "credentials_rejected",
            "Authentication failed: transport shut down or saw EOF": "connection_closed_during_authentication",
        }.get(str(exc), "unclassified")
        emit({"state": "stopped", "error_type": type(exc).__name__,
              "phase": phase, "phase_elapsed_seconds": round(time.monotonic() - phase_started, 3),
              "timings_seconds": dict(timings), "auth_timeout_seconds": opts.auth_timeout,
              "reason": safe_reason,
              "note": "No automatic retry. Check trust/profile, network, or current SSH credentials."})
        return 2
    finally:
        if auth_lock is not None:
            auth_lock.release()
        if client is not None:
            client.close()
        if transport is not None:
            transport.close()
        if sock is not None:
            sock.close()


if __name__ == "__main__":
    raise SystemExit(main())
