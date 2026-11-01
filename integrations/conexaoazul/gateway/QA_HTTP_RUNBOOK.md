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
| Close metadata draft | `POST /v1/drafts/{32 lowercase hex job_id}/close` | Empty body; signed path; tenant-owned; state=closed; never cancel a SupoClip task |
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

Metadata drafts close on demand when 24 hours have elapsed since creation.
Expiry is applied atomically on subsequent prepare, list or read requests;
**there is no daemon or cron**, so expiration and deletion are not time-exact.
Closed rows remain as idempotency tombstones for 30 days after closure,
then are purged on a subsequent request. The same idempotency key on a closed
row returns HTTP 409 `idempotency_closed`; callers must generate a new key.
The signed close route returns `{job_id,state:closed,execution:DISABLED}`.
No close operation stops, deletes, exports or publishes a SupoClip task.
A real multi-process tenancy/retention solution needs approved storage and
scheduled cleanup; do NOT use this SQLite prototype to promise SLA retention.

Replay nonces are transactionally persisted in SQLite; same idempotency key
and payload with a fresh signature yields the same job ID, a modified payload
with the same idempotency key yields HTTP 409, and 3 pending drafts/tenant
yields HTTP 429.

Known response codes: 201 created, 200 idempotent/read, 400 malformed
transport, 401 bad signature/replay, 403 forbidden operation, 404 missing
tenant-owned draft, 409 idempotency conflict or previously closed key, 413 too large, 422 policy
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


## QA media evidence gate — independent upload checks (not wired to HTTP)

`gateway/media_evidence.py` now supplies a separate, explicit-opt-in local
media attestation function for future private uploaded files. It is **not** called
from the ASGI routes, so preparing a draft does **not** mean rights or
duration were independently validated.

- Accept only a verified server-side tenant key and opaque `upload:<id>` reference.
  The file must live in `<QA_ROOT>/<tenant>/<id>.mp4` under a trusted, private
  root. Open directory and file descriptors with `O_NOFOLLOW`, reject hard
  links, nonregular files and anything exceeding 1,000,000,000 bytes.
- SHA-256 streaming hash is computed from file bytes; it must exactly match an
  independently approved `RightsApproval.source_sha256` from a **trusted rights
  system**, also matching tenant, source ref, approver, rights record and validity
  window. A caller-provided `rights_confirmed=true` is **not** that evidence.
- The optional explicit `ffprobe_fd` wrapper invokes an approved FFprobe
  binary with fixed arguments, a previously-opened Linux descriptor,
  20-second timeout and `file`-only protocol whitelist. It requires a
  sandboxed no-egress QA execution environment.
- Reject missing/untrusted probe, non-MP4 headers, duration outside 1–1800 s,
  claim deviating more than 2 s, multiple video streams, unapproved codecs,
  unexpected attachments and dimensions exceeding 3840×2160.
- Compare inode/device/size and nanosecond mtime/ctime before and after the
  media probe to catch ordinary in-place file changes. Production-level race
  prevention may require copying to immutable tenant-specific object storage
  with digest-based retrieval before parsing.
- The return value is a metadata-only
  `{source_sha256,size_bytes,duration_seconds,rights_ref,...,execution:"DISABLED"}`
  observation. **No video processing**, cloud upload, HTTP request, n8n
  workflow, Odoo write, YouTube download, publication or email occurs.

The checks are useful only when a trusted approval system, a secured media
ingest/upload ticket and a separately reviewed FFprobe sandbox are present.
Unit tests use synthetic bytes, an injected fake probe and synthetic approval
records; a passing test **is not a real media or legal rights audit**.

### Media-to-gateway wiring gate

The signed draft API currently permits `rights_confirmed` and a caller
duration claim to create metadata drafts; this remains acceptable **only**
while execution is disabled. Before any live job or remote engine invocation,
the BlueOps orchestration layer must require a matching independently verified
media attestation bound to the exact verified tenant, source hash, rights proof
and one-time job ID. Failing any step must deny job execution.

The user-selected rights record must be checked by human review and a secure
persisted approval store; do not accept arbitrary `RightsApproval` objects
constructed from submitted JSON as proof. If files can contain faces/voices,
review privacy basis, access, retention and cross-tenant isolation.
