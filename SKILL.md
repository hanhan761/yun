---
name: yun
description: Connect and operate authorized Linux and Windows SSH hosts from one self-describing RSA PEM per target, with pinned host identity, 初始化文件夹 (initialize the current folder for local coding and remote storage/compute), bounded source releases, file transfers, durable compute, safe production deployment, and authorized Cloudflare DNS. Use when the user invokes /yun, $yun, yunskills, or yun技能, says “用 yun 初始化这里/这个文件夹” or “把这里的存储和计算交给 yun”, names 3090, 4090, 工作站, or 服务器 as a remote target, supplies a yun_*.pem, or requests remote host control, onboarding, synchronization, deployment, or computation.
---

# 云

Use the bundled control plane. Treat a `YUN-BUNDLE-V1` PEM as the portable source
of truth and the user-local registry/known-hosts files as reproducible cache.
Never reconstruct a private connection from conversation history.

## 用户常用机器名称

Resolve the user's machine name using this user-approved mapping before selecting
a target. These are conversational aliases; keep the existing registry IDs and
PEM filenames. Obtain all connection details from the registered target or its
validated PEM, never from an alias or an inferred GPU/network address.

| 用户称呼 | 登记目标 ID |
| --- | --- |
| `3090`、`3090电脑`、`3090工作站` | `linux-new` |
| `4090`、`4090工作站`、`工作站` | `workstation` |
| `服务器`、`云服务器` | `wenshanzhike-edge` |

- A specific number takes precedence over a generic noun: `3090工作站` means
  `linux-new`, while `工作站` alone means `workstation`.
- Accept the registered IDs as well. Use the resolved ID in every CLI target
  argument, including `--confirm-target`; describe the machine to the user by
  their familiar name.
- When the user names one machine, select and probe only that machine, then
  perform the requested task without asking them to confirm the mapping.
  If it is absent or unreachable, report that target's problem; do not switch
  to another machine. If multiple machines are explicitly requested, follow
  the requested scope for each.
- For a follow-up that omits the machine name, retain the unambiguous active
  target. If there is no unambiguous target, ask only which machine to use.
- Names select the machine, not additional authority or capabilities. Preserve
  its registered roles, protection, and workload restrictions; in particular,
  do not deploy or proxy MatterSwarm on `wenshanzhike-edge`.

## Start every run

1. Resolve this skill directory. If the user supplied an exact self-describing
   PEM path, run `python scripts/yunctl.py import-pem PATH`; never search for it.
2. Otherwise run `python scripts/yunctl.py init`, then `targets`, and match the
   requested target using the aliases above.
3. If the target remains absent, take the onboarding branch. Otherwise run
   `python scripts/yunctl.py probe TARGET` before its first operation this turn.
4. Read the selected branch reference before acting. Read
   [references/registry.md](references/registry.md) as well only when creating,
   replacing, or diagnosing the local target registry.

For a Windows target, read [references/windows.md](references/windows.md) before
onboarding or operation. Select commands from the registered remote `platform`,
not the controller's OS. Missing `platform` means Linux for legacy compatibility.
Windows registration uses `--platform windows --role server`; the PEM carries
that platform on import. Windows has no tmux compute or sudo-authorize support.

Never invent or scan for a host. Never bypass an unknown host with
`StrictHostKeyChecking=no` or `accept-new`. Stop when the target, account, or
server fingerprint cannot be verified through an authorized channel.

## Onboarding branch

For Linux read [references/onboarding.md](references/onboarding.md); for Windows
read [references/windows.md](references/windows.md). Then generate a
unique client key locally, install only its `.pub` half, verify and pin the
server's host key out of band, run `register`, accept with `probe`, and finish
with `bundle-pem TARGET`. Only the resulting PEM needs to travel with this Skill.

Complete onboarding only after strict non-interactive login, registered `probe`,
bundle validation, and an isolated `import-pem` all pass. An unbundled generated
PEM is only a key; a validated self-describing PEM is the portable connection.

## Compute branch

For Linux only, read [references/compute.md](references/compute.md), then use `yunctl.py` for the
submit → status/logs → fetch or cancel → cleanup lifecycle.

Complete a job only after observing a terminal state and exit code, reviewing a
redacted log summary, and fetching or verifying every requested result. A job
ID proves submission, not completion.

## 初始化文件夹

Treat “用 yun 初始化文件夹”, “用 yun 初始化这里”, and requests to put this
folder's storage and compute on yun as this feature. “这里” means the current
working directory in the user's project, not this Skill's directory. First
inspect that directory, its `AGENTS.md`, and any `.yun-workspace.json`; reuse
an unambiguous target and remote root recorded for this project. Do not copy
either value from a different project.

Read [references/workspace.md](references/workspace.md). Use
`scripts/yun_workspace.py` for initial setup and bounded source releases. An
empty folder gets minimal project guidance; an existing project keeps its
files and instructions. Inspect existing project rules before reconciling
their storage and compute paths. The workspace helper currently requires one
registered Linux target with both `server` and `compute` roles. Do not infer a
missing target or remote root; ask only for a value that the request and this
project cannot establish. Initialization does not authorize migration or
deletion of existing local data.

## Server branch

Read [references/servers.md](references/servers.md), then use `probe`, declared
`exec` intent, and bounded `upload`/`download` operations.

For source synchronization, static publication, application/image deployment,
database migration, or any mutation on a resource-constrained production host,
also read [references/fragile-production-deployments.md](references/fragile-production-deployments.md).
Apply its release safety gate before the first production mutation. On a
protected, resource-constrained, or previously deployment-stalled production
target, refuse an ordinary release path that builds runtime artifacts on-host,
including a project-owned script that does so. Do not partially run that path.
Return the rejected step and the repository-specific off-host-build,
immutable-artifact, no-build activation path. An exceptional on-host build is
not implicitly authorized by a deployment request; consider it only under the
reference's separate exception procedure.

For availability, recovery, or outage questions, follow the layered health
check in `references/servers.md`. Report host reachability, application origin,
ingress connector or reverse proxy, and public endpoint separately. Never infer
that a server is down from a public HTTP error alone, or that a public service
has recovered from SSH reachability alone.

Complete a mutation only after verifying the requested outcome. For deployment
or configuration work, preserve and identify a tested rollback path.

## Cloudflare DNS branch

Read [references/cloudflare.md](references/cloudflare.md). For a one-off subdomain
on an existing locally managed Cloudflare Tunnel, prefer the manual dashboard CNAME
workflow; reserve `scripts/yun_cloudflare.py` for repeated automation or when the
user explicitly requests API-based DNS control. Keep any token outside the Skill
and let only the adapter receive it through a hidden local prompt or decrypt it
in-process.

Plan DNS changes before applying them. Require explicit user authority for the
exact record, independently verify public DNS and HTTPS after an apply, and
retain the prior record value as the rollback path.

## Authority and safety

- Treat invocation as authority only for the requested target and outcome.
- Perform read-only inspection on a registered target. Require an explicit user
  request before writes, restarts, deployment, cancellation, billable compute,
  firewall/DNS changes, or public cutover.
- Pass `--confirm-target TARGET` for protected-target writes, uploads, job
  submission, cancellation, and cleanup. This verifies target selection; it
  does not replace user authority.
- Never open, print, copy into the Skill, or return private-key bodies,
  passphrases, populated `.env` files, API keys, cloud tokens, or secret-manager
  values. Let only `yunctl.py bundle-pem` stream a key locally into a restricted,
  validated candidate for atomic in-place replacement. Let only the bundled
  Cloudflare adapter accept a token through a hidden prompt and decrypt it
  locally in-process; it must never emit the value.
- Never put secrets in command arguments, submitted scripts, logs, target
  metadata, or summaries.
- Preserve unrelated workloads. Inspect identity, disk, ports, active jobs, and
  service ownership before a mutation.
- Prefer reversible operations. Refuse recursive deletion, destructive Git,
  disk formatting, account lockout, or key rotation without exact authority and
  verified path/target boundaries.

## Control-plane entry point

Run from the skill directory:

```text
python scripts/yunctl.py --help
```

The CLI accepts only imported or registered targets, verifies hostname, port,
user, exact PEM, client fingerprint, dedicated known-hosts cache, and pinned
host-key fingerprint before network use. It disables SSH config and ambient
agents on every command. The PEM embeds public connection metadata, never a
second credential; its RSA private body remains directly OpenSSH-compatible.

Ordinary server control requires only Python 3, the system OpenSSH client, a
reachable Linux or Windows OpenSSH server, and one bundled PEM. Windows also
needs Windows PowerShell 5.1 on the target and `sftp` on the controller. Remote
Windows command-line operations do not provide RDP or interactive desktop control.
Registry and known-hosts cache are
generated on import. Tailscale, cloud SDKs, MCP, and user SSH config are not
required by the Skill. The optional compute branch also requires remote Bash,
tmux, and setsid.
