# Blue AI Video Studio — media proof → tenant-owned draft binding (QA OFFLINE)

**Status 2026-11-01:** implemented as a Python-only internal boundary in
SupoClip fork draft PR #1. **Not** exposed through ASGI HTTP, MCP, n8n,
Odoo, container service, CLI endpoint or any worker.

This document specifies the contract between
`gateway/media_evidence.py`,
`gateway/evidence_binding.py`,
`gateway/core.py` and
`gateway/state.py`.

## Supported sequence — no network

1. `POST /v1/drafts` (HMAC) creates **metadata-only** `prepared` draft.
   `rights_confirmed=true` and client duration are only provisional claims,
   **not evidence**. Unknown fields and client-supplied `tenant_id` are denied.
2. A future **trusted internal QA service** configures
   `TrustedUploadAttestor(qa_root=..., rights_lookup=..., probe_fn=...)`.
   This service must run with approved server-side identity, encrypted/private
   credentials, no public network egress and a separately reviewed rights
   repository. `rights_lookup(tenant, upload_ref)` must never be implemented
   by blindly deserializing request JSON into a `RightsApproval`.
3. The internal caller signs `POST /internal/drafts/{job_id}/attest`
   with an empty raw request body. **This is an internal method signature
   binding, not a publicly registered HTTP route.**
4. `BlueVideoGateway.attest_draft_offline` authenticates the request via
   HMAC and resolves the verified tenant only from its server-owned keyring.
   Missing/closed/foreign draft, YouTube URLs and absent configured attestor
   fail closed.
5. The trusted rights lookup must yield an active approved record for the
   exact tenant, upload ref and rights record referenced by the draft.
6. The attestor opens only private `upload:<opaque_id>` files within that
   tenant's QA root, hashes bytes with SHA-256, compares to approved digest
   and probes duration, format, codecs and dimensions. A real FFprobe binary
   is **not** executed by the unit suite; tests inject a fake probe.
7. The gateway transactionally binds the measured result to
   `draft_evidence.job_id`, **checking again** that the job is still
   prepared, tenant matches, consent ref matches, source ref matches and
   measured duration is within two seconds of draft claim. Closure and TTL
   expiry invalidate this binding.
8. The only response is
   `{job_id,evidence_status:"verified",created:true|false,execution:"DISABLED"}`.
   No media path, HMAC secret, rights document, external SupoClip task, render,
   export or social publish is returned or performed.

### Failure behavior

| Failure | Outcome |
| --- | --- |
| HMAC missing/invalid/replayed or wrong method/path | denied before rights-store access |
| Missing service-configured attestor | `trusted_media_attestor_not_configured` |
| Missing/revoked/mismatched rights approval | evidence denied and NOT persisted |
| Media hash/duration mismatch or unsupported content | evidence denied and NOT persisted |
| Concurrent tenant closure during media probe | SQLite binding rejects closed job |
| Same exact verified evidence repeated | idempotent return `created=false` |
| Changed hash/rights data for existing draft | deny conflict; no overwrite |
| Cross-tenant job access | no draft/evidence returned or bound |
| Draft expired/closed | attestation unavailable; stored evidence invalidated |
| Existing evidence but attempt to run SupoClip network client | denied, `network_execution_not_implemented` |

## What this absolutely does NOT prove

- We have **not** verified any actual client media, usage rights, IP ownership
  or LGPD consent. Unit tests operate on synthetic bytes and artificial
  approvals only.
- We have **not** exercised real FFprobe in an isolated container. The
  provided `ffprobe_fd` helper is only an explicit opt-in technical primitive.
- The code is not a proof of multi-process database safety, KMS/secret
  management, cloud storage ACL, immutable object versioning, or cross-tenant
  access at the native SupoClip API.
- An existing evidence record does **not** guarantee rights have not been
  revoked, or that a mutable file is unchanged after inspection. Before
  any actual processing, authorization **must be revalidated against the
  rights store**, the media must be verified or pinned to an immutable private
  object SHA, and the engine must receive only a tenant-bound approved upload
  ticket. No implementation of that worker gate exists here.
- SQLite is an offline single-process test ledger, **not production storage**.
  Closing a draft clears evidence lazily; an independently reviewed audit
  trail and retention policy are still missing.
- We have not deployed a gateway, registered a new n8n workflow or changed
  a production service.

## Explicit gates for fixed Odoo 19 QA

The separate Odoo closed-draft contract is in the
[BlueApps19 draft PR #1405](https://github.com/conexaoazul/BlueApps19/pull/1405).
Do not install it or integrate with actual QA database before authorizing
a separate QA deployment. The earlier PR #1403 was merged externally;
do not equate a merge with a proven runtime deployment.

Before a real test, collect a reviewed QA storage path and tenant ACL,
non-production signing keyring and rotation plan, genuine rights repository
and revocation mechanism, pinned FFprobe/runtime image digest, CPU/memory
sandbox, network egress deny, test fixture/license records, smoke plan,
rollback, and evidence artifact locations. Verify no public social accounts
or production customer identifiers are configured.

### Offline regression

```bash
python -m unittest discover -s integrations/conexaoazul/tests -v
```

This command opens no server, sends no data to external providers, does not
run FFprobe for real and performs no Odoo or production modifications.
