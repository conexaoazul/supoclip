"""QA-only, read-only AWS S3 cross-tenant denial probe.

Uses a single externally configured restricted SDK session to retrieve
its actual STS caller identity and make one S3 HeadObject request for a
*foreign* tenant's exact pinned object version. Proves only that this
specific call received a well-formed AccessDenied (403). It does NOT
prove universal IAM policy safety, list/get permissions, all S3 versions,
valid legal rights, bucket immutability, or runtime media isolation.

No clients, accounts, policies, keys or endpoints created here.
"""

import re

from .media_evidence import HASH_RE, TENANT_RE

_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{2,61}[a-z0-9]$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{4,159}$")
_ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
_ARN_RE = re.compile(
    r"^arn:aws:sts::[0-9]{12}:assumed-role/[A-Za-z0-9+=,.@_-]+/"
    r"[A-Za-z0-9+=,.@_-]+$"
)


class QATenantIsolationDenied(ValueError):
    """An independent foreign-tenant denial proof cannot be trusted."""


class QAAwsCrossTenantHeadDeny:
    """Session is created with **foreign-tenant** QA credentials.

    The expected assumed-role ARN and account must be configured by the
    operator out of band. Do NOT accept them or tenant identity in
    untrusted request input. The SDK session must produce *both* the STS
    and S3 clients so their credential source is the same. In live QA,
    obtain an independent auditable identity/permissions record too.
    """

    def __init__(self, *, session, foreign_tenant_id,
                 expected_account_id, expected_assumed_role_arn):
        if (not callable(getattr(session, "client", None))
                or not isinstance(foreign_tenant_id, str)
                or TENANT_RE.fullmatch(foreign_tenant_id) is None
                or not isinstance(expected_account_id, str)
                or _ACCOUNT_RE.fullmatch(expected_account_id) is None
                or not isinstance(expected_assumed_role_arn, str)
                or _ARN_RE.fullmatch(expected_assumed_role_arn) is None
                or expected_assumed_role_arn.split(":")[4] != expected_account_id):
            raise ValueError("trusted_qa_foreign_principal_required")
        self._session = session
        self._foreign_tenant_id = foreign_tenant_id
        self._account = expected_account_id
        self._arn = expected_assumed_role_arn

    def __call__(self, *, tenant_id, bucket, key, version_id):
        """Return True **only** for authenticated distinct-tenant 403."""
        if (not isinstance(tenant_id, str)
                or TENANT_RE.fullmatch(tenant_id) is None
                or tenant_id == self._foreign_tenant_id
                or not isinstance(bucket, str)
                or _BUCKET_RE.fullmatch(bucket) is None
                or not isinstance(version_id, str)
                or _VERSION_RE.fullmatch(version_id) is None
                or not isinstance(key, str)):
            raise QATenantIsolationDenied("invalid_cross_tenant_context")

        prefix = "tenants/" + tenant_id + "/sha256/"
        suffix = ".mp4"
        if (not key.startswith(prefix) or not key.endswith(suffix)
                or HASH_RE.fullmatch(key[len(prefix):-len(suffix)]) is None):
            raise QATenantIsolationDenied("invalid_object_namespace")
        try:
            sts = self._session.client("sts")
            s3 = self._session.client("s3")
            identity = sts.get_caller_identity()
        except Exception as exc:
            raise QATenantIsolationDenied("foreign_identity_unavailable") from exc
        if (not isinstance(identity, dict)
                or identity.get("Account") != self._account
                or identity.get("Arn") != self._arn):
            raise QATenantIsolationDenied("foreign_identity_mismatch")

        try:
            response = s3.head_object(
                Bucket=bucket, Key=key, VersionId=version_id)
        except Exception as exc:
            payload = getattr(exc, "response", None)
            error = payload.get("Error") if isinstance(payload, dict) else None
            metadata = (payload.get("ResponseMetadata")
                        if isinstance(payload, dict) else None)
            # NotFound, BadCredentials, timeout, TLS and generic 403 are
            # not sufficient. Only the structured AWS AccessDenied is
            # accepted, under the freshly verified distinct principal.
            if (isinstance(error, dict)
                    and error.get("Code") == "AccessDenied"
                    and isinstance(metadata, dict)
                    and metadata.get("HTTPStatusCode") == 403):
                return True
            raise QATenantIsolationDenied("foreign_head_not_proven_denied") from exc
        # A successful HEAD is a security failure: never surface metadata.
        del response
        raise QATenantIsolationDenied("cross_tenant_head_unexpectedly_allowed")
