# 新服务器接入：一台服务器一个 PEM

This branch is for Linux. For a native Windows OpenSSH target, use
[windows.md](windows.md), including Windows key ACLs and `--platform windows`.

## 1. Establish authority and dependencies

Obtain a unique lowercase target name, host/IP, SSH port, SSH user, network
reachability, roles, and an authorized bootstrap channel such as provider
console, KVM, cloud-init, or an existing administrator account. Do not scan for
hosts.

Ordinary control needs only Python 3 and OpenSSH on the controller and reachable
sshd on Linux. Do not require Tailscale, a cloud SDK, MCP, or `~/.ssh/config`.

Initialize the external registry for first-time server onboarding:

```text
python scripts/yunctl.py init
```

## 2. Generate the target's only client identity

```text
python scripts/yunctl.py keygen TARGET_NAME
```

This creates exactly:

```text
~/.ssh/yun_TARGET_NAME.pem      # RSA-4096 private key in PEM encoding
~/.ssh/yun_TARGET_NAME.pem.pub  # public half installed on the server
```

The PEM is intentionally unencrypted so an authorized agent can use it without
a password prompt, SSH agent, or secret-manager dependency. The tool applies
restrictive local permissions. Never overwrite or reuse a target's PEM, protect
the controller account, keep the private `.pem` only on that controller, and
install only `.pem.pub`. The tool prints paths and the public fingerprint,
never private contents.

## 3. Install only the public half

Through the authorized bootstrap channel, append the single `.pem.pub` line to
the target account's `~/.ssh/authorized_keys`, then enforce:

```text
~/.ssh                 0700
~/.ssh/authorized_keys 0600
```

Prefer a dedicated account. Disable password/root login where operationally
safe and constrain public exposure with the user's chosen network controls.

## 4. Pin the server identity out of band

On the trusted server console, obtain the ED25519 host public key and
fingerprint:

```text
sudo cat /etc/ssh/ssh_host_ed25519_key.pub
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
```

Verify the fingerprint through an independent trusted channel. Create a
dedicated local file `~/.ssh/yun_TARGET_NAME.known_hosts` containing the verified
host public key prefixed by `HOST` for port 22 or `[HOST]:PORT` otherwise. Do not
trust `ssh-keyscan` alone over the same network being authenticated.

## 5. Register the direct connection

```text
python scripts/yunctl.py register TARGET_NAME \
  --host VERIFIED_HOST \
  --port 22 \
  --user VERIFIED_USER \
  --pem ABSOLUTE_PATH/yun_TARGET_NAME.pem \
  --known-hosts ABSOLUTE_PATH/yun_TARGET_NAME.known_hosts \
  --host-fingerprint SHA256:VERIFIED_FINGERPRINT \
  --role server \
  --description "AUTHORIZED PURPOSE"
```

Add `--role compute` only when remote Bash, tmux, and setsid jobs are authorized;
add `--protected` for production/shared targets. `register` refuses a missing or
non-PEM identity, missing known-hosts file, or fingerprint mismatch.

## 6. Accept

```text
python scripts/yunctl.py probe TARGET_NAME
```

The probe uses direct OpenSSH flags with `-F none`, the exact PEM, no SSH agent,
strict checking, and only the dedicated known-hosts file. For compute targets,
also complete one bounded success/fetch job and one disposable cancellation job.

## 7. Make the PEM portable

After the registered probe succeeds, embed only the verified public connection
record into the existing PEM:

```text
python scripts/yunctl.py bundle-pem TARGET_NAME
```

For a protected target, add `--confirm-target TARGET_NAME`. The command builds a
restricted same-directory candidate, proves OpenSSH derives the same client
fingerprint, and then atomically replaces the original. It does not create a
persistent private-key backup or alter the server-side public key.

The resulting `YUN-BUNDLE-V1` file remains a directly usable RSA PEM. Its first
comment line carries target name, host, port, user, roles/protection, the
verified ED25519 host key, and client/server SHA-256 fingerprints. These are
public connection facts; the RSA private body remains unchanged.

On another controller, carry only this Skill and that PEM, then run:

```text
python scripts/yunctl.py import-pem ABSOLUTE_PATH/yun_TARGET_NAME.pem
python scripts/yunctl.py probe TARGET_NAME
```

`import-pem` restricts copied-key permissions, derives and checks the client
public fingerprint, checks the embedded host binding, and recreates the local
registry and known-hosts cache. The `.pub`, original registry, and original
known-hosts file do not need to travel. Network reachability and the already
installed server-side public key are still required.
