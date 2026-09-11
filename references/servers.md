# 已授权服务器操作闭环

The command examples below use Linux. For `platform: windows`, read
[windows.md](windows.md) and use PowerShell equivalents for host, service, disk,
and application checks. The same target verification and layered health reporting
apply. `probe` selects the platform automatically; `exec-script` handles Windows
cmdlets and pipelines, and Windows upload/download use SFTP with absolute drive paths.

## Inspect

Use only names returned by:

```text
python scripts/yunctl.py targets
```

Start with `probe`. Declare additional command intent explicitly:

```text
python scripts/yunctl.py exec TARGET --read-only -- hostname
python scripts/yunctl.py exec TARGET --read-only -- systemctl is-active SERVICE
```

A PEM/known-hosts/host-fingerprint mismatch is an identity incident. Stop and
verify the change out of band; never weaken strict checking.

### Layered service health check

For questions such as “is the server down?”, “has the workstation recovered?”,
or “is the website working?”, determine each layer independently:

1. **Registered target** — run `init`, `targets`, and `probe`; use only the
   requested registered target. Do not substitute a similarly named server or
   probe an unrelated legacy host.
2. **Host** — record identity, uptime, disk, memory, and relevant runtime state.
   A failed public request does not prove that the host is down.
3. **Application origin** — inspect the owning service/container, its health and
   restart count, the active release or image, and call the private/local health
   endpoint from the target. Avoid reading populated environment files.
4. **Ingress** — inspect the actual connector or reverse proxy used by the
   authoritative deployment topology, such as `cloudflared`, Caddy, or Nginx.
   Do not assume that an older proxy configuration remains authoritative.
5. **Public endpoint** — from the local client, verify DNS and HTTPS for every
   user-facing hostname and its health endpoint. Capture status and provider
   error code without exposing headers or payloads that may contain secrets.

Use read-only commands unless the user explicitly authorizes a repair. Typical
checks, adapted to the registered target and documented service names, include:

```text
python scripts/yunctl.py probe TARGET
python scripts/yunctl.py exec TARGET --read-only -- systemctl is-system-running
python scripts/yunctl.py exec TARGET --read-only -- systemctl is-active SERVICE
python scripts/yunctl.py exec TARGET --read-only -- docker ps
python scripts/yunctl.py exec TARGET --read-only -- curl --fail --max-time 10 ORIGIN_HEALTH_URL
```

Classify the result precisely:

- **Host unavailable**: registered target probe fails; application and ingress
  state remain unknown unless independently evidenced.
- **Origin unavailable**: host is reachable but the local application health
  check fails.
- **Ingress unavailable**: origin is healthy but the active connector/proxy is
  stopped, disconnected, or misrouted.
- **Public route unavailable**: host, origin, and ingress are healthy but public
  DNS, TLS, hostname routing, or provider edge checks fail.
- **Recovered end to end**: target probe, origin health, ingress state, and all
  required public endpoints pass in the same inspection window.

When multiple historical topologies exist, use current deployment records,
active release metadata, running processes, and live routing together. State
which topology is authoritative and mark conflicting legacy configuration as
historical; never collapse “server”, “workstation”, “origin”, and “public
service” into one status.

Report a compact evidence matrix with the inspection timestamp:

```text
Host: reachable/unreachable/unknown
Application origin: healthy/unhealthy/unknown
Ingress: healthy/unhealthy/unknown
Public endpoint(s): healthy/unhealthy/unknown
Overall: recovered/degraded/down/indeterminate
```

If a layer cannot be checked because its target is not registered or its
authoritative topology is unknown, say so and request the exact registered
target or self-describing PEM path. Never invent or scan for a host.

## Mutate

Use a write only for the user's requested outcome:

```text
python scripts/yunctl.py exec TARGET --write -- sudo systemctl restart SERVICE
python scripts/yunctl.py exec PROD --write --confirm-target PROD -- COMMAND
python scripts/yunctl.py upload PROD LOCAL REMOTE --confirm-target PROD
```

Before changing a service or deployment:

1. Capture target identity, current state, disk, ports, dependencies, and a
   rollback artifact or previous configuration.
2. Validate candidate syntax/configuration before activation when supported.
3. Apply the smallest bounded change.
4. Verify service state, health, logs, external behavior, persistence, and
   restart policy as applicable.
5. Roll back when acceptance fails and rollback remains data-safe.

Never combine unrelated cleanup with the requested mutation.

## Transfer

```text
python scripts/yunctl.py upload TARGET ./artifact.tar.gz /tmp/artifact.tar.gz
python scripts/yunctl.py download TARGET /remote/result.json ./downloads/result.json
```

Verify checksums before activation. Do not download or display private keys,
populated environment files, cloud credentials, or secret-store exports.

When the CLI lacks an operation, extend its direct connection path instead of
falling back to ambient SSH config. Preserve every authority, identity, secret,
and verification gate in `SKILL.md`.
