# Windows SSH 接入与运维

Applies to native Windows 10/11 or Windows Server with Microsoft OpenSSH Server
and Windows PowerShell 5.1. The controller can be Windows or Linux with Python 3,
OpenSSH `ssh`, `ssh-keygen`, and `sftp`. WSL sshd is a separate Linux target;
do not label it Windows simply because the physical computer runs Windows.

## Connect a new Windows host

Use the authorized target address, account, and trusted console. A skill upgrade
alone does not authorize configuring a particular host. When host onboarding is
requested, complete its normal setup without asking for redundant permission.

1. Inspect the target through its trusted console: `Get-Service sshd`, the
   listener on the chosen SSH port, the effective firewall rule, and
   `%ProgramData%/ssh/sshd_config`. Confirm which account will receive the key.
2. If OpenSSH Server is missing, install the Windows capability from an elevated
   PowerShell session using
   `Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0`.
   Start `sshd` and configure its startup type when authorized for onboarding.
   Inspect any installer-created firewall rule. Use the user's intended private
   network or source-address scope; do not automatically expose public SSH.
3. On the controller run `python scripts/yunctl.py keygen TARGET`. Install only
   the resulting `.pem.pub` line through the trusted console. Preserve existing
   authorized keys, append only when absent, and save UTF-8 without BOM.
4. Use the effective `AuthorizedKeysFile` configuration. With Microsoft's default:
   standard users use their profile's `.ssh/authorized_keys`; members of the local
   Administrators group use `C:/ProgramData/ssh/administrators_authorized_keys`.
   For the latter, remove inherited permissions and permit only SYSTEM and
   Administrators. The locale-independent SID grants are
   `*S-1-5-18:F` and `*S-1-5-32-544:F` with `icacls.exe`. Inspect existing explicit
   grants too; `/inheritance:r` does not remove those. For a standard account,
   grant the verified account and SYSTEM access and ensure other users cannot
   modify its key directory/file. Do not replace unrelated keys or permissions
   on broad parent directories. Keep the private PEM on the controller.
5. Obtain the server public host key and fingerprint on the trusted target:

   ```powershell
   Get-Content -LiteralPath 'C:/ProgramData/ssh/ssh_host_ed25519_key.pub'
   ssh-keygen.exe -lf C:/ProgramData/ssh/ssh_host_ed25519_key.pub -E sha256
   ```

   Independently verify them. Create the controller's dedicated known-hosts file
   using that public key, prefixed with the verified hostname (or `[HOST]:PORT`).
   Never read the server private host key or trust `ssh-keyscan` alone.
6. Register, probe, and bundle from the skill directory, replacing the placeholders:

   ```text
   python scripts/yunctl.py init
   python scripts/yunctl.py register win-pc --platform windows --host VERIFIED_HOST --port 22 --user VERIFIED_USER --pem ABSOLUTE_PEM_PATH --known-hosts ABSOLUTE_KNOWN_HOSTS_PATH --host-fingerprint SHA256:VERIFIED_FINGERPRINT --role server --protected
   python scripts/yunctl.py probe win-pc
   python scripts/yunctl.py bundle-pem win-pc --confirm-target win-pc
   ```

   `--user` accepts ASCII local names, numeric names such as `13081`, and
   `contoso\alice`. Use the verified local/domain account name; Microsoft Entra
   accounts are not supported by Windows OpenSSH key authentication. Do not
   substitute a different account without the user's direction.
7. Verify importing the PEM into an isolated registry via `YUN_TARGETS_FILE`,
   then a strict registered probe. Preserve and restore the previous environment
   override. Complete onboarding only after an actual SSH login succeeds.

The tool launches `powershell.exe -NoProfile -NonInteractive -EncodedCommand`
explicitly. It supports the default cmd.exe shell and a PowerShell default shell;
changing `HKLM/SOFTWARE/OpenSSH/DefaultShell` is unnecessary. Custom shells such
as Bash require separate verification. PowerShell encoding transports Unicode
and quoted text; it is not encryption and must never contain credentials.

## Operations

```text
python scripts/yunctl.py probe win-pc
python scripts/yunctl.py exec win-pc --read-only -- whoami.exe
python scripts/yunctl.py exec-script win-pc ./inspect.ps1 --read-only
python scripts/yunctl.py exec-script win-pc ./change.ps1 --write --confirm-target win-pc
python scripts/yunctl.py upload win-pc ./artifact.zip C:/Users/13081/artifact.zip --confirm-target win-pc
python scripts/yunctl.py download win-pc C:/Users/13081/result.json ./downloads/result.json
```

`probe` prints `YUN_PROBE_OK` after its required checks, then a JSON record of
hostname, account, Windows version, uptime, system drive, memory, and scheduler.
Treat nonzero exit status as failure even if output was produced. It does not
check an application's health; inspect the owning service and endpoint separately.

`exec` takes native executable arguments. It preserves Windows argument quoting
and the executable's exit code. Use `exec-script` for PowerShell cmdlets, named
parameters, variables, or pipelines; e.g. an `inspect.ps1` containing:

```powershell
Get-Service -Name sshd | Select-Object Name, Status, StartType
Get-Volume | Select-Object DriveLetter, Size, SizeRemaining
```

`exec-script` accepts an existing UTF-8 `.ps1` up to 2 KiB, subject to the encoded
command length limit. Errors stop the script and return nonzero; explicit `exit`
and the last native exit code propagate. In scripts with several native commands,
check `$LASTEXITCODE` after each command, since later successes can overwrite it.
For larger scripts, upload the reviewed file and use
`exec ... -- powershell.exe -NoProfile -NonInteractive -File C:/path/script.ps1`.
The uploaded script must implement its own exit/error handling and obey the
target's execution policy. `--read-only` is an intent declaration, not a sandbox;
review the script and use `--write` for mutations. Never read or submit secret files.

Transfers use an SFTP batch over the same pinned SSH identity. Remote paths must
name one file with an absolute drive path (`C:/...` or `C:\...`). Spaces and
Unicode are supported; glob syntax, relative paths, directory targets, UNC paths,
and alternate data streams are rejected. The destination parent on the remote
host must already exist. Create it with an authorized PowerShell operation if
needed. Upload/download may overwrite the exact destination file, so inspect it
and preserve a rollback copy when replacing valuable data. Verify SHA-256 hashes
with `Get-FileHash -LiteralPath PATH -Algorithm SHA256` before using an artifact.

Windows supports the `server` role only. The CLI rejects Windows `compute` and
`sudo-authorize` requests. Native Task Scheduler jobs, RDP, and interactive GUI
control are not implemented. SSH operations run with the registered account's
existing permissions; they do not elevate it or bypass UAC.

## Diagnose connection failures

Distinguish missing target registration, network/listener failure, host-key
mismatch, public-key authentication failure, and remote command failure. When
authentication fails, inspect the effective key file, its ACL and account group
membership through the trusted console. Do not loosen host checks or silently
fall back to passwords. Inspect Event Viewer `OpenSSH/Operational` with redaction.
If SSH succeeds but probe fails, inspect the shell and PowerShell/CIM errors;
do not report the host as unreachable just because a Linux command was used.

Sources: [Microsoft server configuration](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration),
[Microsoft key authentication](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement).
