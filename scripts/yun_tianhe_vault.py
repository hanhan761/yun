"""Current-Windows-user DPAPI storage for the explicitly authorized ln5 account.

Enrollment takes credentials only from private stdin. No plaintext export CLI.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
import pathlib
import subprocess
import sys


class Blob(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]


def identity(profile):
    fields = ("target", "host", "port", "username", "host_key_type", "host_fingerprint")
    return {**{k: profile[k] for k in fields}, "version": 1}


def entropy(profile):
    return hashlib.sha256(json.dumps(identity(profile), sort_keys=True).encode()).digest()


def dpapi(data, context, *, decrypt=False):
    if os.name != "nt":
        raise OSError("Windows current-user DPAPI is required.")
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    source_buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    context_buffer = (ctypes.c_ubyte * len(context)).from_buffer_copy(context)
    source = Blob(len(data), source_buffer)
    extra = Blob(len(context), context_buffer)
    result = Blob()
    fn = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    fn.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.POINTER(Blob),
                   ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    fn.restype = wintypes.BOOL
    try:
        # UI_FORBIDDEN only: deliberately NOT CRYPTPROTECT_LOCAL_MACHINE.
        if not fn(ctypes.byref(source), None, ctypes.byref(extra), None, None, 1,
                  ctypes.byref(result)):
            raise OSError("DPAPI operation failed; no credential fallback.")
        return ctypes.string_at(result.data, result.size)
    finally:
        ctypes.memset(source_buffer, 0, len(data))
        if result.data:
            ctypes.memset(result.data, 0, result.size)
            kernel.LocalFree(result.data)


def vault_path(profile):
    # Derive an account-specific filename without storing credentials or names in the skill.
    import yun_tianhe_password as session
    label = hashlib.sha256((profile["target"] + "\0" + profile["username"]).encode()).hexdigest()[:20]
    return session.local_appdata() / "yun" / "private-tianhe" / (label + ".dpapi")

def restrict_directory(directory):
    """Dedicated directory only; never change ACLs of shared runtime parents."""
    system = pathlib.Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32"
    result = subprocess.run([str(system / "whoami.exe"), "/user", "/fo", "csv", "/nh"],
                            capture_output=True, check=True,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    import csv
    sid = next(csv.reader([result.stdout.decode("utf-8", "replace").strip()]))[-1]
    if not sid.startswith("S-1-"):
        raise ValueError("Could not resolve the current user SID.")
    subprocess.run([str(system / "icacls.exe"), str(directory), "/inheritance:r",
                    "/grant:r", f"*{sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"],
                   capture_output=True, check=True,
                   creationflags=subprocess.CREATE_NO_WINDOW)


def save(profile, username, password, *, replace=False):
    if username != profile["username"] or not isinstance(password, str) or not password:
        raise ValueError("Only the configured account and a nonempty credential are accepted.")
    path = vault_path(profile)
    payload = json.dumps({"identity": identity(profile), "password": password}).encode("utf-8")
    encrypted = dpapi(payload, entropy(profile))
    payload = None
    # Verify before writing without printing the decrypted result.
    if json.loads(dpapi(encrypted, entropy(profile), decrypt=True))["password"] != password:
        raise ValueError("DPAPI verification failed.")
    path.parent.mkdir(parents=True, exist_ok=True)
    restrict_directory(path.parent)
    if path.exists() and not replace:
        raise FileExistsError("Credential exists; explicit --replace is required.")
    # No plaintext temporary file, even on replacement. Flush before atomic swap.
    import tempfile
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, suffix=".dpapi.tmp", delete=False) as stream:
            temporary = pathlib.Path(stream.name)
            stream.write(encrypted)
            stream.flush()
            os.fsync(stream.fileno())
        if not replace and path.exists():
            raise FileExistsError("Credential already exists.")
        # Windows rename refuses an existing destination; replace requires opt-in.
        if replace:
            os.replace(temporary, path)
        else:
            os.rename(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    return path


def load(profile):
    path = vault_path(profile)
    if path.stat().st_size > 65536:
        raise ValueError("Credential blob exceeds bounded size.")
    data = json.loads(dpapi(path.read_bytes(), entropy(profile), decrypt=True))
    if set(data) != {"identity", "password"} or data["identity"] != identity(profile):
        raise ValueError("Credential identity mismatch.")
    password = data.pop("password")
    if not isinstance(password, str) or not password:
        raise ValueError("Credential is empty.")
    return profile["username"], password


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--replace", action="store_true", help="Explicitly replace an existing encrypted credential.")
    opts = parser.parse_args()
    try:
        import yun_tianhe_password as session
        profile = session.load_profile(opts.profile)
        username, password = session.credentials_from_pipe()
        try:
            path = save(profile, username, password, replace=opts.replace)
        finally:
            password = None
        print(json.dumps({"state": "credential_encrypted", "target": "tianhe-ln5",
                          "username": profile["username"], "path": str(path),
                          "scope": "Windows CurrentUser", "plaintext_export": False}), flush=True)
        return 0
    except Exception as exc:
        # Exception text/JSON parser errors may contain input; emit type only.
        print(json.dumps({"state": "stopped", "phase": "credential_enrollment",
                          "error_type": type(exc).__name__}), flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
