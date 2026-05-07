# Recon Bridge — Operator Runbook (Shadowbroker side)

The recon bridge exposes `/bridge/*` endpoints that authorized clients
(typically deep-eye) consult before running a scan. It serves two
purposes:

1. **Scope authorization** — a signed POST to `/bridge/scope/check`
   verifies a target falls within an engagement's scope manifest.
2. **OSINT enrichment** — a signed GET to `/bridge/enrich/<target>`
   returns aggregated intel (Shodan, region dossier, CT logs,
   geopolitics alerts) so clients can adapt their recon.

Both endpoints require HMAC-SHA256 signatures and a 60-second timestamp
window. Replays are blocked via an in-memory nonce cache.

For architecture and security rationale, see the design spec at
`deep-eye/docs/superpowers/specs/2026-05-05-shadowbroker-integration-design.md`.

This runbook is the **how**.

---

## Setup (one-time per environment)

The bridge is **opt-in**: existing Shadowbroker deployments are
unaffected unless explicitly enabled.

### 1. Generate an HMAC secret per client

```bash
# 32 random bytes, hex-encoded
python3 -c "import secrets; print(secrets.token_hex(32))"
# -> example: 9d1c4f8b2a6e... (32 bytes / 64 hex chars)
```

Hand the secret to the deep-eye operator out-of-band (signal, password
manager, anything *not* email or chat). Pair it with a `key_id` you
both agree on (e.g. `deep-eye-prod-1`).

### 2. Drop scope manifests in `SCOPE_MANIFEST_DIR`

The default is `backend/config/scope/`. Each manifest is a YAML file
named after its `scope_token` (e.g. `engagement-acme-2026q2.yml`).
See `backend/services/recon_bridge/scope_manifest.py` for the schema —
the deep-eye repo ships an example at
`config/scope/example-engagement.yml`.

Manifest expiry (`expires_at`) is **mandatory** — there is no "never"
option. Plan renewal ahead of expiration.

### 3. Set environment variables

```bash
# Master switch — bridge stays unmounted unless this is set to "true".
export SHADOWBROKER_BRIDGE_ENABLED=true

# Where scope manifests live. Default: backend/config/scope
export SCOPE_MANIFEST_DIR=/etc/shadowbroker/scope

# Authorized HMAC keys (comma-separated keyid:hex pairs).
export RECON_BRIDGE_HMAC_KEYS="deep-eye-prod-1:9d1c4f8b...,deep-eye-prod-2:abcd..."
```

### 4. Restart the backend

```bash
# In the backend/ directory:
uvicorn main:app --host 0.0.0.0 --port 8000

# Or via the Docker compose stack — set the env vars in your .env and
# `docker compose up -d backend`.
```

You should see in the logs:
```
recon-bridge: mounted /bridge/* with N HMAC key(s) from scope_dir=...
```

If the bridge is misconfigured (no keys, missing scope dir), the rest
of Shadowbroker still boots but `/bridge/*` is **not** mounted and you
will see:
```
recon-bridge wiring FAILED, /bridge/* will not be served: ...
```

That's the fail-closed posture: half-configured = not configured.

## Operating

### Verify it's up

```bash
# Unsigned request — should 401:
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8000/bridge/enrich/example.com
# -> 401
```

### Key rotation

Add the new key to `RECON_BRIDGE_HMAC_KEYS` alongside the old one,
restart, then have all clients move to the new `key_id`. Once no client
is using the old key, drop it from the env var and restart again.

### Scope manifest updates

Manifests are read at boot for the default `SCOPE_MANIFEST_DIR` and
loaded per-request from disk. To update a manifest, just rewrite the
YAML — no restart needed for content changes (only env-var changes
require a restart).

### Disable the bridge

Set `SHADOWBROKER_BRIDGE_ENABLED=false` (or unset) and restart. The
rest of Shadowbroker is unaffected.

## Troubleshooting

### `recon-bridge wiring FAILED: enabled but no HMAC keys configured`
`RECON_BRIDGE_HMAC_KEYS` is empty or all entries are bad hex. Check the
env var is exported in the same shell that launched uvicorn.

### `recon-bridge wiring FAILED: scope manifest dir ... does not exist`
`SCOPE_MANIFEST_DIR` points to a non-existent path. Create the dir and
drop at least one `.yml` manifest in it before restart.

### Clients getting 401 with `signature mismatch`
- The client is signing with a different secret than `RECON_BRIDGE_HMAC_KEYS`
  has for that `key_id`. Re-share the secret out-of-band.
- Clock skew — both sides need NTP. The verifier rejects timestamps
  more than 60 seconds out.
- A reverse proxy in front of Shadowbroker is rewriting the body or
  path. The bridge signs `request.url.path` (Starlette-decoded). If the
  proxy adds/removes path components, signatures will not match.

### Clients getting 401 with `replay detected`
Two clients with the same `key_id` are sending identical signed
requests within the 5-minute nonce TTL. Either coordinate the clients
or split the credential (separate `key_id` per client instance).

### Bridge mounted but `/bridge/scope/check` returns 404
The `scope_token` doesn't have a matching `<token>.yml` file in
`SCOPE_MANIFEST_DIR`. Drop one in or fix the client's config.

### Aggregator `feed_errors` showing for known feeds
- `shodan: ...` → `SHODAN_API_KEY` env not set, or rate-limited.
- `region_dossier: ...` → ip-api.com rate-limited (45/min/IP free tier).
- `ct_logs: ...` → crt.sh slow / down. Best-effort feed; keep going.
- `geopolitics: ...` → GDELT cache empty (the recurring scheduler
  populates it; first request after boot may be empty).

These are degraded-but-OK; clients still get a 200 with partial intel
and `feed_errors` listing what failed.

## Logs to grep

```bash
# Successful bridge wiring
grep "recon-bridge: mounted" /var/log/shadowbroker.log

# Wiring failures
grep "recon-bridge wiring FAILED" /var/log/shadowbroker.log

# Per-request feed timeouts (warn-level)
grep "Enrichment feed .* timed out" /var/log/shadowbroker.log
```
