# Cloudflare DNS and bounded hostname changes

Use this branch only for an authorized Cloudflare DNS zone. Keep the API token
outside the Skill and repository. The bundled adapter is the only component
allowed to decrypt the token in-process; it must never print, log, upload, or
place the token in a command argument.

## Preferred one-off subdomain workflow

For one new hostname on an existing locally managed Cloudflare Tunnel, prefer
one manual dashboard CNAME over API-token onboarding. Use this sequence:

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
Reserve API automation for repeated or bulk DNS work, or when the user
explicitly requests it.

## API automation for repeated changes

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
cd C:\Users\13081\.codex\skills\yun
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

## DNS writes

Treat DNS changes as public cutovers. First run `dns-upsert` without `--apply`
and inspect the plan. Apply only after explicit user authorization, adding both
`--apply` and `--confirm-name` with the exact fully-qualified record name.

The adapter supports bounded A, AAAA, and CNAME upserts. It refuses records
outside the configured zone, conflicting record types, and ambiguous duplicate
records. It does not delete records. After a write, independently verify public
DNS, HTTPS behavior, the origin service, and rollback readiness.
