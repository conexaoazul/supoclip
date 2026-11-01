# BlueOps video drafts — private QA HTTP contract (NOT DEPLOYED)

**Status 2026-11-01:** in-memory ASGI transport and domain tests only. No live
listener, TLS certificate, reverse proxy, authorization service, secret
store, outbound SupoClip client, n8n workflow, or Odoo integration exists.

Source: `conexaoazul/supoclip` draft PR #1, branch
`feat/blueops-qa-pilot-preflight`.

## Routes implemented at code level

| Operation | Endpoint | Action |
|---|---|---|
| Prepare draft | `POST /v1/drafts` | Store tenant-scoped metadata only, never start video processing |
| List own drafts | `GET /v1/drafts` | Enumerate only principal's tenant |
| Read own draft | `GET /v1/drafts/{32 lowercase hex job_id}` | Return minimal status; alien tenant gets 404 |
| Publish / export / delete / arbitrary paths | everything else | Explicit deny |

`POST /v1/drafts` expects exactly the six JSON fields shown in the companion
contract at
https://github.com/conexaoazul/BlueApps19/blob/feat/blue-ai-video-studio-pilot-contracts/docs/blue_ai_video_studio/contracts/job-request.schema.json

- `source_ref` = `https://www.youtube.com/watch?v=ABCdef123_4` or
  `upload:ABCdef123456` (opaque; **upload bridge is not implemented**)
- `rights_confirmed: true` and `consent_ref` = opaque rights record reference
- `clip_length` one of `auto,short,medium,long`
- `idempotency_key` opaque 8–128 ASCII chars
- `source_duration_seconds` = integer 1–1800, **untrusted caller claim**

Keys `tenant_id`, `social_account_id`, `publish`, additional metadata and
client-provided job state are rejected. The response has an opaque
`job_id`, `state: prepared`, `created: true|false`, and
`execution: DISABLED`, with no URL, rights record or secret.

## Request signing (internal only)

The future authorized BlueOps adapter supplies a QA-scoped private signing
key; an n8n workflow must **never** embed the key in JSON/code/sticky notes.
Each request has four mandatory headers:

- `x-blue-key-id` (server-defined key mapping to tenant, not a tenant field)
- `x-blue-timestamp` (Unix epoch integer, ±300 seconds)
- `x-blue-nonce` (cryptographically generated, unique 16–96 chars)
- `x-blue-signature` (lowercase hex HMAC-SHA256)

The signature is

```text
HMAC_SHA256(
  secret,
  METHOD + "\n" + EXACT_PATH + "\n" + KEY_ID + "\n" +
  UNIX_TIMESTAMP + "\n" + NONCE + "\n" + SHA256(raw_body).hexdigest()
)
```

For GET, the raw body is empty. Sign EXACT bytes, no reserialization after
signing. HTTP adapter rejects duplicate headers, encoded paths,
query strings, unexpected content types, mismatched content lengths,
oversized bodies (8192 bytes), non-HTTPS scope and forbidden verbs.

Replay nonces are transactionally persisted in SQLite; same idempotency key
and payload with a fresh signature yields the same job ID, a modified payload
with the same idempotency key yields HTTP 409, and 3 pending drafts/tenant
yields HTTP 429.

Known response codes: 201 created, 200 idempotent/read, 400 malformed
transport, 401 bad signature/replay, 403 forbidden operation, 404 missing
tenant-owned draft, 409 idempotency conflict, 413 too large, 422 policy
validation failed, 426 TLS required, 429 tenant queue cap, 503 unavailable.

## Deployment gate — NOT cleared

Code-level `scope["scheme"]=="https"` is only a **defense in depth** check.
It does **not** terminate TLS, validate a cert, prove private ingress, or
verify the identity of a reverse proxy. The approved ingress must:

1. Limit reachability to a dedicated isolated QA network, bind the listener to
   loopback/private address, and use trustworthy HTTPS/mTLS termination.
2. Prevent clients from spoofing `scope.scheme` through forwarded headers:
   only a specifically trusted proxy may set forwarded metadata.
3. Load QA-scoped keyrings from an approved secret manager, with rotation,
   revocation and zero secrets in Git/n8n/Odoo.
4. Place SQLite on an approved **isolated** QA volume, enforce restrictive
   permissions and encrypted backup/retention policy. Plan migration to
   dedicated PostgreSQL before multi-process or actual customer tenancy.
5. Enforce request timeouts, connection limits, WAF/private firewall, egress
   restrictions and resource quotas at ingress and orchestration layer.
6. Require independent source ownership, media duration verification, content
   classification, privacy and license gates before any SupoClip job.
7. Implement validated egress to permitted provider endpoints, DNS rebinding
   prevention, redirect policy, URL normalization, and upload MIME/size checks
   **before** implementing any outbound client.
8. Keep native SupoClip social OAuth, billing and publishing disabled at
   **runtime**, not just UI flags. No public social account credentials.
9. Run fixed QA Odoo 19 DB under separate explicit GO; never connect production.
10. Produce trace/redacted logs, SBOM, CVE and AGPL legal analysis, measurable
    costs and rollback plan prior to changing readiness state.

The module intentionally exports a `create_app(gateway)` factory and
**does not** publish a global `app` for auto-discovery. None of this document
authorizes installing a runner, gateway, mTLS certificate or integration.

## Offline regression test

```bash
python -m unittest discover -s integrations/conexaoazul/tests -v
```

The tests instantiate the ASGI callable directly in memory. They never open
a port or contact SupoClip, n8n, cloud APIs or Odoo.

## Outstanding architecture gaps

- ASGI lifespan readiness / ingress / service configuration not implemented.
- HMAC key lifecycle, audit, threat model review and secret storage missing.
- Durable event/outbox/webhook callbacks, DLQ and n8n retries missing.
- Real video probe, signed upload bridge, worker and rendering not implemented.
- MCP tools in BlueOps remain **specification only**, never exposed.
