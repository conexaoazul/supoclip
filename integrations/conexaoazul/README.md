# Conexão Azul — SupoClip QA adapter preflight (NO DEPLOY)

**Status:** DRAFT, offline-only. No code path is imported into SupoClip runtime.
**Baseline SHA:** `4bc76f83b3427808464f117473ee61083c65cf1f` (2026-10-31).
**Internal Odoo/BlueOps contract:** https://github.com/conexaoazul/BlueApps19/pull/1403
**Source:** https://github.com/conexaoazul/supoclip
**Tracked upstream:** https://github.com/FujiwaraChoki/supoclip

## Decision

Keep this AGPL-3.0 SupoClip engine **separate** from the Conexão Azul proprietary
Odoo 19 module. Never copy upstream runtime code into BlueApps19. All
cross-system access must eventually pass through a private BlueOps video
gateway, which obtains tenant identity from an authenticated, verified principal.

This branch adds a machine-readable **QA evidence preflight** plus a **network-free
BlueOps gateway core** under `gateway/`: HMAC-SHA256 verification, signed
method/path/body binding, SQLite nonce replay protection, per-tenant persistent
idempotent drafts, a 3-pending-requests limit, strict source syntax validation,
and a canonical SupoClip task request **PLAN ONLY**. The gateway accepts a
server-configured `key_id → (tenant_id, secret)` map and never trusts a tenant
field in the request. It does not expose HTTP, call a remote API, execute jobs,
render videos, use MCP, publish posts or connect to production.

The code is a controlled domain prototype, **not an attestation of production
readiness**. The caller-declared duration and consent MUST be independently
verified before real media processing. The SQLite DB must be created inside
an explicitly approved QA volume and never pointed at a production disk.

This repository also includes an intentionally failing unverified template
and offline unit tests.

### What this is NOT

- NOT an approved infrastructure plan, deployment artifact or Docker override.
- NOT proof that QA resources, DB, Redis, firewall, DNS, media storage or LLM
  models are configured, and NOT proof of enterprise multitenancy.
- NOT a working n8n/Odoo/MCP integration, or a social-posting authorization.
- NOT a network/SSRF sandbox: dynamic DNS, redirects, runtime egress, remote
  download path, metadata-IP and URL size policies must be implemented and
  tested in the eventual gateway and infrastructure before sending media.

## QA-only execution gate

The preflight consumes a nonsecret JSON **evidence snapshot** in the shape of
`qa-evidence-template.json` (no credentials, tokens or private hosts), e.g.:

```bash
python -m unittest discover -s integrations/conexaoazul/tests -v
python integrations/conexaoazul/qa_preflight.py /path/to/qa-evidence.json
# The new domain tests are included automatically by the command above.
```

**Do not run SupoClip** from this folder. Copy the evidence template outside
the repository, complete boolean claims based on *actual independently
verified evidence*, and retain the output in a restricted location. A passing
self-declared snapshot is only a preflight; it does **not** prove controls at
runtime. Any unverified field must remain false and fail closed.

Minimum controls before a live QA test:
- Non-production host, isolated Postgres/Redis and object storage, private bind,
  outbound traffic restrictions, worker concurrency + resource limits.
- `SELF_HOST=true`, `ALLOW_UNSIGNED_BACKEND_AUTH=false`, CPU-only build,
  non-dev secrets, disabled sign-up, verified limited QA credentials.
- Pilot hard limits: 30 minutes, 1 GB source, 10 candidate clips, 1 worker.
- No configured social accounts; block social publish endpoints and egress
  even though `NEXT_PUBLIC_SOCIAL_PUBLISHING=off` only changes presentation.
- No use of SupoClip MCP's default hosted endpoint. For QA, `SUPOCLIP_API_URL`
  must point to the isolated authorized gateway/backend, with scoped key and
  denylisted harmful tools.
- Rights evidence attached to source; no external communications or
  publication without a separate human approval gate.
- Human review of upstream AGPL duties and SBOM/CVE scan before commercialization.

### PR gates

1. Both PRs remain draft while static tests run.
2. No merge, install, deploy, new DNS, secrets, n8n activation or production
   changes without explicit separate authorization.
3. No media processing until runtime security, network isolation, tenancy,
   storage retention, licensing and cost caps are demonstrated.

## Evidence ownership

- Engineering: isolated QA resources and immutable commit/image digests.
- Security/BlueOps: auth, egress, SSRF, ACL, trace logs, quotas and DLQ.
- Marketing/editorial: permitted sources, PT-BR subtitles, human approval.
- Product/Odoo: model/ACL review, QA fixed database, canonical asset handoff.

## Offline gateway protocol (prototype only)

- The only prepared action is `POST /v1/drafts`; its **raw JSON bytes** are
  signed along with the method, path, key ID, Unix timestamp and one-time nonce.
- An authorized principal is resolved **solely** from a non-user-controlled
  keyring maintained on the future BlueOps server.
- Signed fields: `source_ref`, `rights_confirmed`, `consent_ref`,
  `clip_length`, `idempotency_key`, `source_duration_seconds`.
  Unknown fields (including `tenant_id`) are rejected.
- HMAC header transport is NOT implemented. Future gateway HTTP adapter must
  require TLS, private ingress, secure timestamps/nonces, per-key revocation,
  uniform error handling, audited key rotation and no auth bypass.
- Replay nonce claims and draft reservations use SQLite transactional uniqueness.
  A repeated **newly signed** identical intent returns the same prepared job ID;
  a reused nonce is denied, and an idempotency-key conflict is denied.
- The response is `{job_id, state: "prepared", created, execution: "DISABLED"}`;
  the read-only list also requires a distinct signed envelope.
- `prepare_upstream_task` maps an authenticated prepared YouTube draft to a
  `POST /tasks/` *description only*. It raises for runtime network execution,
  uploads needing a separate approval, and any unsafe operation.
- Spec and docs parity with the proprietary Odoo adapter are managed through
  https://github.com/conexaoazul/BlueApps19/pull/1403 .

**Additional runtime gates not implemented:** HTTP/TLS layer, KMS/Vault,
multiple worker processes/nonces DB tuning, per-client authorization including
object access, verified media length, DNS-rebinding and redirect validation,
egress firewall, DLP, cost caps, HMAC webhook signature verification,
durable audit trail and Odoo 19 QA API integration.
