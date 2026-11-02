# Blue AI Video Studio — Production promotion gate (2026-11-01)

## Decision: BLOCKED / NO PRODUCTION DEPLOY

Authorized user intent: "Deploy prod @Conector N8N @BlueOps Platform Orchestrator".
The **request** is a deployment GO, **not** evidence that mandatory
security, QA, operational, licensing and rollback prerequisites are satisfied.

This runbook was produced by preflight only. **No merge, image push, service
deployment, Odoo installation, external video processing, publishing, or
production workflow activation was executed.**

### Exact source and CI baselines (recheck before promotion)

| Source | Latest observed head | Observed CI | State |
| --- | --- | --- | --- |
| `conexaoazul/supoclip#1` | `2c7184084394e0836db68972fdfddd39035c79a4` | offline, general tests, image security PASS | DRAFT / OPEN, unmerged |
| `conexaoazul/BlueApps19#1405` | `5030d3efc161441506db87f677b14914be2301e0` | offline contract, static, OCI fallback PASS | DRAFT / OPEN, unmerged |
| `conexaoazul/BlueApps19#1403` | merged `e2e0099c334dfb10dd0f771aa514b48b1962fbf6` | code merged; addon still `installable=False` | MERGED does not equal deployed |

The SupoClip internal gateway implements **metadata-only**, signed QA
`prepared` drafts, `close`, and a Python-internal-only rights/media
snapshot. All contain `execution: DISABLED`. There is **no** production
worker client, tenant-safe media delivery path, revocation enforcement at
worker consumption, public media QA or commercial rights clearance.

The Odoo addon explicitly declares `installable=False`. Do not flip
this flag until Odoo 19 fixed QA installation and record-rule/ACL smoke.

### n8n execution and active-version readback

- Inactive, manual-only **preflight checklist**:
  https://conector.conexaoazul.com/workflow/o7EmHrB5MdqeAdIA
- Workflow ID: `o7EmHrB5MdqeAdIA`.
- Verified readback: `active=false`, `activeVersionId=null`,
  nodes = Manual Trigger, Set, Code; **zero credentials, no HTTP,
  SSH, Execute Command, social, e-mail, Meta or DB nodes**.
- Synthetic manual test execution `1010063`: `success`, output
  `status=BLOCKED`, `execution=DISABLED`, `publish=DENIED`.
  This confirms the guardrail works, **NOT** that production deploy passed.
- Existing `e8h3rvBSj7QGY9TP` QA SupoClip disk/RAM/inodes read-only
  workflow is inactive, and its linked subworkflows were not validated;
  do NOT activate or run it as a replacement for a direct infra baseline.

### What the infra connectors actually showed

- Portainer environment 36 `cluster1-azul`: Swarm active, 5 nodes,
  3 managers; this is **not** a service health or a capacity guarantee.
- Portainer environment 37 `oci-db-dr-1`: Docker reachable but not
  an active Swarm manager.
- The `portainer_services_list` command failed for service-level inventory;
  **no current/desired replica counts, image digest, task failures or
  canary placement are verified**.
- Odoo Ops runtime-status read returned DB `consultas` and image
  `ghcr.io/conexaoazul/blueapps19-consultas:fix-github-20260930`;
  this is a constrained status, not proof about every production Odoo or
  video workload.
- Therefore do not claim the Video Studio is running, and do not change
  a similarly named unrelated service.

### Required independent evidence (all currently BLOCKED)

1. **Image/placement**: resolve immutable target digest from a successful,
   reviewed container build; identify exact production Swarm service,
   network, tenant boundary, placement, baseline replicas/tasks, image and
   error rate. Never use unpinned floating tags.
2. **QA functional**: run real FFprobe inside an approved egress-denied,
   resource-limited sandbox on a **licensed, user-owned** sample.
   Verify 2+ tenants and denied foreign access at native SupoClip media
   API and object storage, not only metadata.
3. **Trusted rights**: independently verified rights store + reviewer
   approvals + revocation, with a recheck at worker handoff.
   Client `rights_confirmed=true` is NOT legal proof.
4. **Immutable media**: private upload ticket, SHA-256/object version,
   strict per-tenant storage ACL, signed short-lived reads, retention and
   deletion proof. No direct public YouTube downloads in commercial pilot.
5. **Runtime execution**: isolated worker adapter and message queue,
   backpressure, per-tenant concurrency, media URL/SSRF egress allowlist,
   CPU/RAM/disk limits, TTL, auditing, cost ceilings, cancellation semantics.
   None of these live runtime controls are implemented and evidenced.
6. **Odoo 19 fixed QA**: installable version reviewed, non-disposable QA
   database smoke (without using production customer data), record rules,
   company switch, UI, approval workflow and uninstall/rollback plan.
7. **Legal/FinOps**: SupoClip AGPL-3.0 network-service obligations reviewed,
   customer media licenses and privacy basis recorded, cloud/model cost cap
   and margin validated. A separate proprietary module license does not
   itself satisfy network-copyleft obligations.
8. **Operational rollback**: precise previous deployment digest,
   image+config snapshot, migration backward-compatibility proof,
   manual abort thresholds, health/readiness smoke, on-call owner,
   monitoring and revert authority.
9. **Change governance**: explicit artifact-to-deploy attestation
   `CODE→CI→ARTIFACT→DEPLOY→RUNTIME→SMOKE→EVIDENCE`.
   The source-side CI alone proves only code/testing.

### Promotion order — ONLY AFTER THE ABOVE ARE PASS

- Phase A: isolated QA real source + rights + FFprobe and two-tenant
  read/write denial; produce redacted, reproducible evidence.
- Phase B: canary **private** production worker with all external
  publication, network downloads, user messaging and customer billing
  disabled by default, and no shared Odoo migrations.
- Phase C: inspect runtime digest, replicas, logs, saturation, media ACL,
  rights revocation, quotas, snapshot cleanup and cost/trace evidence.
- Phase D: widen only after metrics match baseline and security owner GO.
  Do not use n8n workflow publication as implicit authorization to
  send content or messages.

### Rollback/abort conditions

Do not begin promotion without a previously verified immutable release
digest and a rollback to it, plus validated persistent data compatibility.
Abort on any failed tenant isolation, unexpected egress, expired rights,
duplicate content execution, leaked token/URL, unexpected production DB
write, worker instability, error-rate increase, runaway cost or deployment
drift. Roll back only with recorded ownership and environment-appropriate
safe action; **never delete data or force scale to zero blindly**.

### Handoff

- Engineering: implement and prove the runtime worker boundary + media
  immutable store; raise separate changeset and image build evidence.
- Security/Legal: rights and AGPL-3.0 reviews with actual signoff.
- PlatformOps: read-only Portainer service baseline after connector issue,
  then canary/health/rollback plan.
- Odoo owner: fixed QA Odoo 19 installation/smoke; current addon stays
  non-installable in production.
- n8n owner: leave workflow `o7EmHrB5MdqeAdIA` **inactive**, it is a
  read-only advisory manual gate and not a deploy workflow.

**Final gate: BLOCKED; no production deployment was performed.**
