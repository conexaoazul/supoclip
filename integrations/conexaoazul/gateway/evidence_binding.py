"""Offline-only trusted media-attestation boundary for a private QA gateway.

Only a server-configured repository may resolve rights records. This module
contains no HTTP route, background task, SupoClip client or key store.
"""

from .media_evidence import EvidenceDenied, RightsApproval, attest_private_upload


class TrustedUploadAttestor:
    """Trust boundary: injected rights lookup MUST be internal server-side.

    It must not parse the request JSON into RightsApproval and must not fetch
    public URLs. The optional ffprobe callable must run in a separate reviewed
    no-network sandbox when used with real media.
    """

    def __init__(self, *, qa_root, rights_lookup, probe_fn=None):
        if not callable(rights_lookup):
            raise ValueError("trusted_rights_lookup_required")
        self._qa_root = qa_root
        self._rights_lookup = rights_lookup
        self._probe_fn = probe_fn

    def attest(self, *, tenant_id, draft, now):
        if (not isinstance(draft, dict) or draft.get("state") != "prepared"
                or draft.get("tenant_id") != tenant_id):
            raise EvidenceDenied("draft_not_owned_or_prepared")
        source_ref = draft.get("source_ref")
        if not isinstance(source_ref, str) or not source_ref.startswith("upload:"):
            raise EvidenceDenied("uploaded_media_required")
        try:
            approval = self._rights_lookup(tenant_id, source_ref)
        except Exception as exc:
            raise EvidenceDenied("rights_store_unavailable") from exc
        if (not isinstance(approval, RightsApproval)
                or approval.rights_ref != draft.get("consent_ref")):
            raise EvidenceDenied("rights_reference_mismatch")
        result = attest_private_upload(
            qa_root=self._qa_root,
            verified_tenant=tenant_id,
            upload_ref=source_ref,
            claimed_duration_seconds=draft["source_duration_seconds"],
            rights_record=approval,
            now=now,
            probe_fn=self._probe_fn,
        )
        # Cross the state boundary with a strictly reduced, nonsecret payload.
        # width, height, codec etc. are not needed for authorization binding.
        wanted = {
            "tenant_id", "source_ref", "source_sha256", "size_bytes",
            "duration_seconds", "rights_ref", "approved_by",
            "execution", "evidence",
        }
        return {name: result[name] for name in wanted}
