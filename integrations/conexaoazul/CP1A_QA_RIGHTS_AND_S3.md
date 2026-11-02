# CP1a — signed rights, revocation, and private object-version proof

**Status:** offline QA code with verified synthetic smoke; NOT production ready.
**Date:** 2026-11-02. Source: SupoClip fork draft PR #1.

## Exact new code

- `gateway/qa_rights_ledger.py`: QA-only SQLite ledger for independent
  reviewer-signed `RightsApproval` events, permanent same-source uniqueness,
  signed explicit revocation, bounded timestamps and signed data verification
  on every lookup. Service uses **separate** reviewer keys from gateway HMAC
  keys. No HTTP registration or worker dispatch.
- `gateway/qa_s3_object_proof.py`: metadata-only **AWS S3** read-only object
  version validator. Requires an injected trusted version lookup; exact
  key namespace `tenants/<authenticated-tenant>/sha256/<digest>.mp4`;
  AWS endpoint HTTPS; bucket versioning; all four Public Access Block flags;
  nonpublic bucket policy status; `head_object` for a specified version
  with FULL_OBJECT SHA-256 checksum; encrypted object; and S3 Object Lock
  **COMPLIANCE** through at least five more minutes. GOVERNANCE is denied.
  Also requires a live **cross-tenant denial probe** under a separate
  restricted IAM principal before emitting `private_acl_verified=True`.
  The adapter does no PUT, GET body, DELETE, presign, DNS mutation or deploy.
- `gateway/worker_handoff.py` already performs recheck against independent
  rights and object-head callbacks; outputs `execution=DISABLED`,
  `dispatch=false`, `publish=false` even when metadata agrees.
- `tests/test_qa_rights_ledger.py` verifies signatures, tamper detection,
  reviewer identity, duplicate-denial, persistence/revocation and a live
  QA SQLite-injected gateway+worker test with **synthetic media probe**.
- `tests/test_qa_s3_object_proof.py` verifies strict S3 metadata/negative
  IAM requirement using mocks ONLY.
- `tests/smoke_signed_rights_ffprobe.py` (opt-in) creates a temporary
  original one-second H.264 fixture, validates it with real `ffprobe`,
  signs/registers synthetic rights, creates+attests a gateway draft,
  rehearses offline worker checks with **mock object head**, then revokes
  rights and verifies the next handoff is refused.

### Recorded reproducible QA evidence (not production runtime)

- On 2026-11-02, `blueops-oci-worker-1` workspace ran:
  `python3 -m unittest -q test_qa_s3_object_proof test_qa_rights_ledger`
  → 33 tests, `OK`, exit `0` (actual local SQLite; mock S3).
- `python3 smoke_signed_rights_ffprobe.py` → exit `0`,
  `PASS_SYNTHETIC_SIGNED_RIGHTS_ONLY`,
  `real_ffprobe=true`, `rights_revocation_blocks_recheck=true`,
  `real_s3_acl_tested=false`, `deploy_executed=false`.
- Unit tests reuse artificial local review keys and synthetic rights.
  **No legal consent, real IAM policy, bucket retention or customer clip
  was inspected.**
- The isolated workspace is not a deployed workload or production database.

## Remaining hard gates

1. Reviewer identity and digital signatures must be issued by the real
   governance/approval system with authenticated human review; use an
   organization-managed KMS or equivalent, separation of duty, key rotation,
   audit log and fail-closed outage behavior. The QA SQLite repository is
   NOT a production authority and not a tamper-proof revocation store
   against an administrator with database write rights.
2. Choose an isolated AWS S3 QA bucket with Object Lock COMPLIANCE enabled,
   carefully account for **retention irreversibility and storage cost**;
   do not enable retention on existing production buckets as a shortcut.
   A non-AWS S3-compatible provider must be reviewed independently for
   equivalent lock semantics; this AWS-only adapter must fail closed.
3. Configure distinct IAM principals per tenant and a cross-tenant
   deny-only verification principal. Record actual `AccessDenied` evidence
   for `GetObjectVersion` and access to object HEAD/body, and verify
   encryption/bucket/resource policies using independent audit.
   `tenant_deny_probe` in unit tests is a mock and never proves ACL.
4. Implement a version registry in a server-managed database, keyed by
   authenticated tenant + upload reference + complete SHA-256. The current
   injected version callback is only a contract, not a deployed registry.
5. Implement transactionally bound, single-use consumption capability,
   queue backpressure, quotas, isolated rendering and no-egress media
   sandbox. Re-validate rights at the actual consumption boundary to
   close TOCTOU gap; the current offline check is deliberately not atomic.
6. End-to-end fixed Odoo 19 QA smoke with real private upload and 2-tenant
   denial tests; image digest/build provenance, backup/rollback proof,
   CPU/RAM headroom and legal AGPL-3.0 review are still required.
7. No production deploy of this fork, no public proxy or n8n workflow
   activation while any of these gates remain unresolved.

## External technical references

- AWS S3 Object Lock semantics and version protection:
  https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
- AWS Boto3 S3 GetObject/HeadObject checksum semantics:
  https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/get_object.html

**Release decision: BLOCKED; use these modules exclusively for QA evidence.**


## CP1a independent AWS tenant denial probe — added 2026-11-02

- `gateway/qa_tenant_deny_probe.py`: `QAAwsCrossTenantHeadDeny`.
  Requires an injected external session for **foreign-tenant QA IAM**,
  exact expected STS assumed-role ARN and AWS account ID from trusted
  configuration, strictly a different tenant from the object owner, a
  tenant+SHA-pinned object key and a non-null object version.
- Makes read-only `sts.get_caller_identity` and `s3.head_object`.
  Only a structured AWS `AccessDenied` with HTTP 403 from that foreign
  role returns `True`; `NoSuchKey`/404, network errors, invalid identity,
  other 403 conditions and successful foreign HEAD fail closed.
  Never reads object bodies or publishes a media URL.
- It can be injected as the `tenant_deny_probe` of
  `QAAWSObjectProof`; use **one restricted QA boto3.Session** for both
  identity and S3 client. The proof is valid for one principal/key/version
  at one moment only, not all policies or objects.
- Unit tests `tests/test_qa_tenant_deny_probe.py` cover exact identity,
  key, version, forbidden access, 404/other errors and incorrect 403.
- **43 targeted offline tests PASS**, exit 0, running rights, S3 and
  negative IAM contract suites together on `blueops-oci-worker-1`.
  No AWS credentials were supplied or invoked. This does **not**
  constitute a real cross-tenant access denial in a QA bucket.

**Next proof required before promotion:** use a *dedicated* approved QA
bucket, two independently restricted IAM identities, verified pinned
object versions and a real HeadObject denial under the foreign principal.
Audit IAM/bucket/object-lock and positive owner access. Do not reuse
the production `consultas` storage bucket, invent permission settings,
alter Object Lock retention or commit credentials to this public fork.
