"""Fail-closed, read-only AWS S3 object-version evidence adapter for QA.

Only caller-provided, trusted AWS S3 API client methods are used. This
component does NOT provision storage, upload objects, grant IAM permissions,
serve presigned links, read media bytes, or dispatch a worker.

An independent cross-tenant DENY test using a distinct IAM principal MUST
be implemented by the caller's tenant_deny_probe. A real production
authorization system requires verified IAM configuration, recorded approval
and immutable source/version pinned for the entire consumption transaction.
"""

import base64
import binascii
from datetime import datetime, timedelta, timezone
import hmac
import re
from urllib.parse import urlsplit

from .media_evidence import HASH_RE, TENANT_RE, UPLOAD_ID_RE, REF_RE


class PrivateObjectProofDenied(ValueError):
    """Read-only storage proof unavailable; no object URL or credentials."""


_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{2,61}[a-z0-9]$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{4,159}$")


class QAAWSObjectProof:
    """Read metadata of one trusted, pinned object version; fail closed.

    `s3_client` must be authorized for QA bucket metadata only. No boto3
    import is needed by offline tests. Caller supplies a server-side
    `version_lookup(tenant, source, digest)` and a tenant-denial verifier
    using a distinct, restricted IAM principal.

    AWS Object Lock COMPLIANCE is the only accepted mode in this pilot.
    Governance mode may be bypassed by privileged operators and is denied.
    """

    def __init__(self, *, s3_client, bucket, version_lookup,
                 tenant_deny_probe, clock=None):
        if (not isinstance(bucket, str) or
                _BUCKET_RE.fullmatch(bucket) is None or
                ".." in bucket or ".-" in bucket or "-." in bucket):
            raise ValueError("invalid_private_bucket")
        if (not callable(version_lookup) or
                not callable(tenant_deny_probe) or
                not all(callable(getattr(s3_client, method, None)) for method in (
                    "head_object", "get_bucket_versioning",
                    "get_public_access_block", "get_bucket_policy_status",
                ))):
            raise ValueError("read_only_object_dependencies_required")
        # Never silently trust S3-compatible non-AWS providers to implement
        # S3 Object Lock; their semantics must be reviewed separately.
        meta = getattr(s3_client, "meta", None)
        endpoint = getattr(meta, "endpoint_url", None)
        host = urlsplit(endpoint).hostname if isinstance(endpoint, str) else None
        if (not isinstance(endpoint, str) or
                not endpoint.startswith("https://") or
                not isinstance(host, str) or
                not (host == "s3.amazonaws.com"
                     or (host.startswith("s3.") or host.startswith("s3-"))
                     and host.endswith(".amazonaws.com"))):
            raise ValueError("aws_s3_endpoint_required")
        self._client = s3_client
        self._bucket = bucket
        self._lookup = version_lookup
        self._deny = tenant_deny_probe
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def __call__(self, tenant_id, source_ref, digest):
        if (not isinstance(tenant_id, str)
                or TENANT_RE.fullmatch(tenant_id) is None
                or not isinstance(source_ref, str)
                or UPLOAD_ID_RE.fullmatch(source_ref) is None
                or not isinstance(digest, str)
                or HASH_RE.fullmatch(digest) is None):
            raise PrivateObjectProofDenied("invalid_object_context")

        key = "tenants/" + tenant_id + "/sha256/" + digest + ".mp4"
        try:
            version = self._lookup(tenant_id, source_ref, digest)
        except Exception as exc:
            raise PrivateObjectProofDenied("version_registry_unavailable") from exc
        if (not isinstance(version, str)
                or _VERSION_RE.fullmatch(version) is None
                or version == "null"):
            raise PrivateObjectProofDenied("trusted_version_required")

        try:
            bucket_version = self._client.get_bucket_versioning(
                Bucket=self._bucket)
            block = self._client.get_public_access_block(
                Bucket=self._bucket)
            public = self._client.get_bucket_policy_status(
                Bucket=self._bucket)
            head = self._client.head_object(
                Bucket=self._bucket, Key=key, VersionId=version,
                ChecksumMode="ENABLED",
            )
        except Exception as exc:
            raise PrivateObjectProofDenied("object_store_read_unavailable") from exc

        flags = (block.get("PublicAccessBlockConfiguration")
                 if isinstance(block, dict) else None)
        policy = (public.get("PolicyStatus")
                  if isinstance(public, dict) else None)
        if (not isinstance(bucket_version, dict)
                or bucket_version.get("Status") != "Enabled"
                or not isinstance(flags, dict)
                or any(flags.get(f) is not True for f in (
                    "BlockPublicAcls", "IgnorePublicAcls",
                    "BlockPublicPolicy", "RestrictPublicBuckets",
                ))
                or not isinstance(policy, dict)
                or policy.get("IsPublic") is not False):
            raise PrivateObjectProofDenied("private_bucket_policy_unverified")

        if not isinstance(head, dict):
            raise PrivateObjectProofDenied("object_head_invalid")
        now = self._clock()
        until = head.get("ObjectLockRetainUntilDate")
        if (not isinstance(now, datetime) or now.tzinfo is None
                or not isinstance(until, datetime) or until.tzinfo is None
                or head.get("ObjectLockMode") != "COMPLIANCE"
                or until <= now + timedelta(minutes=5)
                or head.get("ServerSideEncryption") not in (
                    "AES256", "aws:kms", "aws:kms:dsse")
                or head.get("VersionId") != version
                or head.get("ChecksumType") not in (None, "FULL_OBJECT")
                or type(head.get("ContentLength")) is not int
                or not 12 <= head["ContentLength"] <= 1_000_000_000):
            raise PrivateObjectProofDenied("immutable_version_unverified")
        encoded = head.get("ChecksumSHA256")
        try:
            expected = base64.b64decode(encoded, validate=True)
        except (TypeError, ValueError, binascii.Error) as exc:
            raise PrivateObjectProofDenied("full_object_checksum_required") from exc
        if len(expected) != 32 or not hmac.compare_digest(expected.hex(), digest):
            raise PrivateObjectProofDenied("full_object_checksum_mismatch")

        # An independently credentialed, negative IAM check is essential:
        # bucket public-access flags alone do NOT prove tenant isolation.
        # This callback returns true only when cross-tenant GetObjectVersion
        # was *actually denied*. The proof cannot be minted by request JSON.
        try:
            denied = self._deny(
                tenant_id=tenant_id, bucket=self._bucket,
                key=key, version_id=version,
            )
        except Exception as exc:
            raise PrivateObjectProofDenied("cross_tenant_probe_unavailable") from exc
        if denied is not True:
            raise PrivateObjectProofDenied("cross_tenant_isolation_unverified")
        return {
            "tenant_id": tenant_id,
            "source_ref": source_ref,
            "source_sha256": digest,
            "size_bytes": head["ContentLength"],
            "version_id": version,
            "object_is_immutable": True,
            "private_acl_verified": True,
        }
