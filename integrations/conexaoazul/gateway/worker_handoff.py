"""QA-only pre-consumption gate: recheck media + rights + immutable-object metadata.

This is *not* an engine adapter, dispatch queue, runtime authorizer, grant
issuer or HTTP endpoint. No network, no SupoClip client, no media export.
All providers MUST be configured server-side; never derive them from a
caller-supplied JSON body. Even a successful response is non-executing.
"""

from .evidence_binding import TrustedUploadAttestor
from .media_evidence import EvidenceDenied, HASH_RE, REF_RE, TENANT_RE
from .state import GatewayState


class WorkerHandoffDenied(ValueError):
    """Safe redacted reason why an offline rehearsal cannot proceed."""


class OfflineWorkerHandoff:
    """Re-check upload immediately before *potential* downstream consumption.

    A future runtime needs a separate atomic, single-use production grant,
    the independently enforced tenant/ACL on real object storage, fresh
    authorization in the worker process, and a dedicated queue. None are
    implemented here.
    """

    def __init__(self, *, state, attestor, object_head):
        if not isinstance(state, GatewayState):
            raise TypeError("gateway_state_required")
        if not isinstance(attestor, TrustedUploadAttestor):
            raise TypeError("trusted_attestor_required")
        if not callable(object_head):
            raise TypeError("trusted_object_head_required")
        self._state = state
        self._attestor = attestor
        self._head = object_head

    def check_offline(self, *, tenant_id, job_id, now):
        """Return a non-executing rehearsal decision, fail-closed on any drift.

        `tenant_id` must originate from authenticated gateway identity;
        caller cannot use this method as an authorization endpoint.
        """
        if (not isinstance(tenant_id, str) or
                TENANT_RE.fullmatch(tenant_id) is None or
                not isinstance(job_id, str) or len(job_id) != 32 or
                any(c not in "0123456789abcdef" for c in job_id) or
                type(now) is not int):
            raise WorkerHandoffDenied("invalid_context")
        draft = self._state.get_for_tenant(tenant_id, job_id, now=now)
        if draft is None or draft["state"] != "prepared":
            raise WorkerHandoffDenied("draft_closed_or_foreign")
        baseline = self._state.get_verified_evidence(
            tenant_id=tenant_id, job_id=job_id, now=now)
        if not baseline:
            raise WorkerHandoffDenied("missing_initial_attestation")
        if not draft["source_ref"].startswith("upload:"):
            raise WorkerHandoffDenied("upload_only")
        try:
            fresh = self._attestor.attest(
                tenant_id=tenant_id, draft=draft, now=now)
        except (EvidenceDenied, ValueError, KeyError) as exc:
            raise WorkerHandoffDenied("fresh_media_or_rights_denied") from exc
        if (fresh.get("execution") != "DISABLED" or
                fresh.get("evidence") != "QA_LOCAL_ATTESTATION_ONLY" or
                fresh.get("tenant_id") != tenant_id or
                fresh.get("source_ref") != draft["source_ref"] or
                fresh.get("source_sha256") != baseline["source_sha256"] or
                fresh.get("rights_ref") != baseline["rights_ref"] or
                fresh.get("size_bytes") != baseline["size_bytes"] or
                abs(fresh.get("duration_seconds", -1000) -
                    baseline["duration_seconds"]) > 0.01):
            raise WorkerHandoffDenied("evidence_changed_or_invalid")

        # Trusted object-store *head* must re-verify tenant namespace, SHA256
        # and immutable object version. A local path or an etag alone is not
        # acceptable. This is a hypothetical injected provider in unit tests,
        # not proof that real object storage is configured.
        try:
            obj = self._head(tenant_id, draft["source_ref"],
                             baseline["source_sha256"])
        except Exception as exc:
            raise WorkerHandoffDenied("private_object_store_unavailable") from exc
        expected = {
            "tenant_id", "source_ref", "source_sha256", "size_bytes",
            "version_id", "object_is_immutable", "private_acl_verified",
        }
        if not isinstance(obj, dict) or set(obj) != expected:
            raise WorkerHandoffDenied("object_proof_invalid")
        version = obj["version_id"]
        if (obj["tenant_id"] != tenant_id or
                obj["source_ref"] != draft["source_ref"] or
                obj["source_sha256"] != baseline["source_sha256"] or
                obj["size_bytes"] != baseline["size_bytes"] or
                type(obj["size_bytes"]) is not int or
                obj["object_is_immutable"] is not True or
                obj["private_acl_verified"] is not True or
                not isinstance(version, str) or
                REF_RE.fullmatch(version) is None or
                HASH_RE.fullmatch(obj["source_sha256"]) is None):
            raise WorkerHandoffDenied("object_proof_mismatch")

        # Re-check lifecycle *again*: a human may close a draft during
        # media inspection or object-head lookup. Still not an atomic
        # production check/consume operation and must not authorize execution.
        latest = self._state.get_for_tenant(tenant_id, job_id, now=now)
        if latest is None or latest["state"] != "prepared":
            raise WorkerHandoffDenied("draft_closed_during_recheck")
        latest_evidence = self._state.get_verified_evidence(
            tenant_id=tenant_id, job_id=job_id, now=now)
        if not latest_evidence or latest_evidence != baseline:
            raise WorkerHandoffDenied("evidence_revoked_during_recheck")

        return {
            "job_id": job_id,
            "rehearsal": "CHECKS_MATCHED",
            "execution": "DISABLED",
            "dispatch": False,
            "publish": False,
            "proof_snapshot_sha256": baseline["source_sha256"],
        }
