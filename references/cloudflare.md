# Cloudflare account, DNS and bounded hostname changes

## Official Cloudflare plugin and OAuth connection

Discover the official Cloudflare MCP and applicable product skill in the current session. Verify the active connection, account and permissions before using them; prior authorization is not proof of access. Prefer the official connection for authorized work and use only the scopes required by the task. The user completes any interactive consent.

Never inspect, copy or publish OAuth tokens. If the connection is unavailable, use the documented bounded fallback only when the user has authorized that operation. Preserve prior DNS and ingress configuration and verify the resulting service and rollback path.

## DNS authority and cutovers

Determine which provider nameservers are authoritative before acting. An
Alibaba DNS console warning that its assigned nameservers are not used can mean
the zone intentionally uses Cloudflare; it does not by itself establish a DNS
security incident. Manage records at the authoritative provider. Never switch
registrar nameservers merely to clear that warning: first inventory all records,
including email, verification, DNSSEC, proxy and Tunnel dependencies, and plan
cutover verification and rollback. DNS resolution is separate from ICP filing
and access-provider approval; verify the actual domain current status.

Before an authorized DNS write, inspect exact records and their prior values,
protect unrelated services, apply only the intended change, then verify public
DNS and the affected HTTPS/origin behavior. Existing user authorization for a
clear outcome covers its necessary changes; ask only if target or scope remains
materially ambiguous. Do not create billable Cloudflare resources without an
explicit request.

## Token adapter and manual dashboard fallback

If the official OAuth connection is unavailable or an independently scoped
zone token is explicitly needed, use the existing bounded adapter or the manual
dashboard workflow below. Keep API tokens outside the Skill and repository.
Only the bundled adapter accepts a token through its hidden local prompt or
decrypts it in-process; it must never print, log, upload, or place it in a
command argument.

## Preferred one-off subdomain workflow

When the official OAuth connection is unavailable, a manual dashboard CNAME can
be simpler than API-token onboarding for one new hostname on an existing locally
managed Cloudflare Tunnel. Use this sequence:

1. Inspect the registered server read-only. Identify the active Tunnel UUID,
   its local config, the exact private service, current health, and existing
   ingress rules. Never infer the service port from the hostname.
2. Add the exact hostname to the Tunnel ingress. Preserve unrelated routes,
   validate a candidate before activation, back up the current config, restart
   only when reload is unsupported, verify registered tunnel connections and
   origin health, and keep the tested rollback path.
3. In Cloudflare Dashboard, open the zone's **DNS > Records**, select
   **Add record**, and enter:
   - Type: `CNAME`
   - Name: the requested subdomain label
   - Target: `<TUNNEL-UUID>.cfargotunnel.com`
   - Proxy status: `Proxied`
   - TTL: `Auto`
4. Verify public DNS A/AAAA resolution, direct HTTPS with certificate
   verification, the root page, and the application API health endpoint. Also
   recheck the original hostname to catch regressions.

The DNS record and Tunnel ingress are separate requirements: DNS routes the
hostname to the Tunnel, while ingress maps that hostname to the private service.
Record both the previous DNS state and server-config backup for rollback.
The authorized official MCP can also create this record after the same checks.

## API-token adapter fallback

### Create a least-privilege token

In Cloudflare, create either a user-owned or account-owned **Custom API Token**,
not a Global API Key. Prefer an account-owned token for durable automation:

- Permission: `DNS Write` (the dashboard may display this as
  `Zone` → `DNS` → `Edit`). This also permits the adapter to inspect the record
  before a bounded create/update.
- Permission: `Zone Read` (the API documentation names this
  `Zone Zone Read`; the dashboard may display `Zone` → `Zone` → `Read`).
- Resource: `Include` → `Specific zone` → the one intended zone
- Do not grant account-wide resources or unrelated permissions.
- Do not substitute `Account DNS Settings Write`; that permission manages
  account-level DNS settings and does not authorize records in a zone.

Cloudflare shows the token once. In a local interactive terminal, run:

```text
cd "$env:USERPROFILE\.codex\skills\yun"
python scripts\yun_cloudflare.py configure --zone matterswarm.com
```

For an account-owned token whose value begins with `cfat_`, the adapter prompts
for the Account ID after the hidden token prompt. Find the 32-character Account
ID from Cloudflare **Account home**: open the menu beside the account name and
choose **Copy account ID**, then paste that value at the Account ID prompt. Do
not put placeholder text in the command. The Account ID is non-secret; the API
token must still be entered only at the hidden prompt.

Paste the token only at the hidden prompt. The adapter resolves exactly one
active zone, automatically verifies either a User Token or an Account Token,
and confirms DNS access before it saves anything. On Windows it stores a
CurrentUser-DPAPI ciphertext under
`%USERPROFILE%\.config\yun\secrets\`; metadata without secrets is stored in
`%USERPROFILE%\.config\yun\cloudflare.json`.

Check without exposing the token:

```text
python scripts\yun_cloudflare.py status
python scripts\yun_cloudflare.py verify
```

If configuration reaches the zone but DNS access returns error `10000`, run
the read-only Account Token diagnostic. It does not store the token or change
DNS:

```text
python scripts\yun_cloudflare.py diagnose --zone matterswarm.com
```

The diagnostic distinguishes a missing DNS permission, a DNS permission bound
to an Account rather than a Zone resource, an explicit deny policy, and a
matching policy that Cloudflare still rejects. Policy details require the token
to include `Account API Tokens Read`; without that permission the command still
reports the endpoint-level access results but marks policy inspection as
unavailable.

## Token adapter DNS writes

Treat DNS changes as public cutovers. First run `dns-upsert` without `--apply`
and inspect the plan. Apply only within the user-authorized outcome, adding both
`--apply` and `--confirm-name` with the exact fully-qualified record name.

The adapter supports bounded A, AAAA, and CNAME upserts. It refuses records
outside the configured zone, conflicting record types, and ambiguous duplicate
records. It does not delete records. After a write, independently verify public
DNS, HTTPS behavior, the origin service, and rollback readiness.
