"""Offline security regression for trusted, tenant-bound upload evidence.

All media is synthetic and the probe is mocked. No real FFprobe, service or
network call occurs; no claims about real media or legal rights.
"""

from dataclasses import replace
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gateway import (AuthFailure, BlueVideoGateway, GatewayState,
                     PolicyFailure, VerificationKey)
from gateway.core import sign_request
from gateway.evidence_binding import TrustedUploadAttestor
from gateway.media_evidence import RightsApproval

NOW = 1793539000
SOURCE = "upload:0123456789abcdef"
CONSENT = "rights:qa-approved-00001"
MEDIA = b"\x00\x00\x00\x18ftypisom" + b"fake synthetic fixture " * 128
DIGEST = hashlib.sha256(MEDIA).hexdigest()
KEYS = {
    "key-a": VerificationKey("tenant-a", b"A" * 32),
    "key-b": VerificationKey("tenant-b", b"B" * 32),
}


def fake_probe(fd):
    import os
    assert os.fstat(fd).st_size == len(MEDIA)
    return {
        "format": {"duration": "120.25", "size": str(len(MEDIA)),
                   "format_name": "mov,mp4,m4a,3gp,3g2,mj2"},
        "streams": [
            {"codec_type": "video", "codec_name": "h264",
             "width": 1280, "height": 720},
            {"codec_type": "audio", "codec_name": "aac"},
        ],
    }


class EvidenceBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        for tenant in ("tenant-a", "tenant-b"):
            (self.root / tenant).mkdir()
        (self.root / "tenant-a" / "0123456789abcdef.mp4").write_bytes(MEDIA)
        self.state = GatewayState(str(self.root / "state.sqlite"))
        self.approvals = {
            ("tenant-a", SOURCE): RightsApproval(
                tenant_id="tenant-a", source_ref=SOURCE, source_sha256=DIGEST,
                rights_ref=CONSENT, approved_by="qa-reviewer-a",
                approved_at=NOW - 60, valid_until=NOW + 3600,
                processing_allowed=True,
            )
        }
        self.lookup_count = 0

        def trusted_lookup(tenant, source):
            self.lookup_count += 1
            return self.approvals.get((tenant, source))

        self.attestor = TrustedUploadAttestor(
            qa_root=self.root, rights_lookup=trusted_lookup,
            probe_fn=fake_probe,
        )
        self.app = BlueVideoGateway(
            keys=KEYS, state=self.state, clock=lambda: NOW,
            upload_attestor=self.attestor,
        )
        self.count = 0

    def tearDown(self):
        self.state.close()
        self.tmp.cleanup()

    def signed(self, *, key_id="key-a", method, path, body=b"", at=NOW):
        self.count += 1
        nonce = "EvidenceNonce" + str(self.count).zfill(18)
        return {
            "key_id": key_id, "nonce": nonce, "timestamp": at,
            "signature": sign_request(
                KEYS[key_id].secret, key_id=key_id, nonce=nonce,
                timestamp=at, method=method, path=path, body=body,
            ),
        }

    def prepare(self, *, key_id="key-a", **changes):
        payload = {
            "source_ref": SOURCE, "rights_confirmed": True,
            "consent_ref": CONSENT, "clip_length": "short",
            "idempotency_key": "qa_evidence_000001",
            "source_duration_seconds": 120,
        }
        payload.update(changes)
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        return self.app.prepare(
            **self.signed(key_id=key_id, method="POST",
                          path="/v1/drafts", body=body),
            body=body,
        )["job_id"]

    def attest(self, job, *, key_id="key-a"):
        auth = self.signed(
            key_id=key_id, method="POST",
            path="/internal/drafts/" + job + "/attest")
        return self.app.attest_draft_offline(job_id=job, **auth)

    def test_success_is_only_recorded_metadata_not_execution(self):
        job = self.prepare()
        result = self.attest(job)
        self.assertEqual(result, {
            "job_id": job, "evidence_status": "verified",
            "created": True, "execution": "DISABLED",
        })
        self.assertEqual(self.lookup_count, 1)
        item = self.state.get_verified_evidence(
            tenant_id="tenant-a", job_id=job, now=NOW)
        self.assertEqual(item["source_sha256"], DIGEST)
        self.assertEqual(item["rights_ref"], CONSENT)
        self.assertEqual(item["size_bytes"], len(MEDIA))
        self.assertEqual(item["duration_seconds"], 120.25)
        self.assertNotIn("source_ref", item)
        self.assertNotIn("approved_by", item)
        self.assertEqual(self.state.get_for_tenant(
            "tenant-a", job, now=NOW)["state"], "prepared")
        self.assertNotIn("external_task_id", result)

    def test_repeated_attestation_is_idempotent(self):
        job = self.prepare()
        self.assertTrue(self.attest(job)["created"])
        self.assertFalse(self.attest(job)["created"])

    def test_foreign_tenant_must_not_get_or_attest_evidence(self):
        job = self.prepare()
        with self.assertRaisesRegex(PolicyFailure, "draft_missing_closed_or_foreign"):
            self.attest(job, key_id="key-b")
        self.assertIsNone(self.state.get_verified_evidence(
            tenant_id="tenant-b", job_id=job, now=NOW))
        self.assertEqual(self.lookup_count, 0)

    def test_unsigned_or_wrong_path_never_reaches_approvals(self):
        job = self.prepare()
        bad = self.signed(
            key_id="key-a", method="POST", path="/v1/drafts/" + job)
        with self.assertRaises(AuthFailure):
            self.app.attest_draft_offline(job_id=job, **bad)
        self.assertEqual(self.lookup_count, 0)
        self.assertIsNone(self.state.get_verified_evidence(
            tenant_id="tenant-a", job_id=job, now=NOW))

    def test_replayed_nonce_denied(self):
        job = self.prepare()
        auth = self.signed(
            method="POST", path="/internal/drafts/" + job + "/attest")
        self.app.attest_draft_offline(job_id=job, **auth)
        with self.assertRaises(AuthFailure):
            self.app.attest_draft_offline(job_id=job, **auth)

    def test_missing_attestor_is_fail_closed(self):
        job = self.prepare()
        bare = BlueVideoGateway(keys=KEYS, state=self.state,
                                clock=lambda: NOW)
        auth = self.signed(
            method="POST", path="/internal/drafts/" + job + "/attest")
        with self.assertRaisesRegex(PolicyFailure, "trusted_media_attestor_not_configured"):
            bare.attest_draft_offline(job_id=job, **auth)
        self.assertIsNone(self.state.get_verified_evidence(
            tenant_id="tenant-a", job_id=job, now=NOW))

    def test_caller_rights_true_does_not_attest_media(self):
        job = self.prepare()
        self.assertIsNone(self.state.get_verified_evidence(
            tenant_id="tenant-a", job_id=job, now=NOW))
        self.assertTrue(self.state.get_for_tenant(
            "tenant-a", job, now=NOW)["state"] == "prepared")

    def test_missing_or_revoked_rights_denied(self):
        job = self.prepare()
        self.approvals.clear()
        with self.assertRaises(PolicyFailure):
            self.attest(job)
        self.assertIsNone(self.state.get_verified_evidence(
            tenant_id="tenant-a", job_id=job, now=NOW))
        self.approvals[("tenant-a", SOURCE)] = RightsApproval(
            tenant_id="tenant-a", source_ref=SOURCE, source_sha256=DIGEST,
            rights_ref=CONSENT, approved_by="qa-reviewer-a",
            approved_at=NOW - 100, valid_until=NOW + 100,
            processing_allowed=False,
        )
        with self.assertRaises(PolicyFailure):
            self.attest(job)

    def test_rights_reference_mismatch_fails_before_probe(self):
        job = self.prepare()
        self.approvals[("tenant-a", SOURCE)] = replace(
            self.approvals[("tenant-a", SOURCE)],
            rights_ref="rights:unrelated-project",
        )
        with self.assertRaisesRegex(PolicyFailure, "rights_reference_mismatch"):
            self.attest(job)
        self.assertIsNone(self.state.get_verified_evidence(
            tenant_id="tenant-a", job_id=job, now=NOW))

    def test_source_sha_change_is_denied(self):
        job = self.prepare()
        (self.root / "tenant-a" / "0123456789abcdef.mp4").write_bytes(
            MEDIA.replace(b"fake", b"FAKE"))
        with self.assertRaisesRegex(PolicyFailure, "rights_approval_missing"):
            self.attest(job)

    def test_wrong_duration_denied(self):
        job = self.prepare(source_duration_seconds=100)
        with self.assertRaisesRegex(PolicyFailure, "duration_mismatch"):
            self.attest(job)

    def test_close_revokes_attestation_and_reopen_denied(self):
        job = self.prepare()
        self.attest(job)
        close_auth = self.signed(
            method="POST", path="/v1/drafts/" + job + "/close")
        self.app.close_draft(job_id=job, **close_auth)
        self.assertIsNone(self.state.get_verified_evidence(
            tenant_id="tenant-a", job_id=job, now=NOW))
        with self.assertRaisesRegex(PolicyFailure, "draft_missing_closed_or_foreign"):
            self.attest(job)

    def test_expiration_revokes_existing_evidence(self):
        job = self.prepare()
        self.attest(job)
        far = NOW + 86401
        self.assertIsNone(self.state.get_verified_evidence(
            tenant_id="tenant-a", job_id=job, now=far))
        self.assertEqual(self.state.get_for_tenant(
            "tenant-a", job, now=far)["state"], "closed")

    def test_youtube_is_not_evidence_attestable(self):
        job = self.prepare(source_ref="https://youtu.be/ABCdef123_4")
        with self.assertRaisesRegex(PolicyFailure, "uploaded_media_required"):
            self.attest(job)

    def test_race_closing_draft_during_probe_cannot_bind(self):
        job = self.prepare()

        def closing_probe(fd):
            auth = self.signed(
                method="POST", path="/v1/drafts/" + job + "/close")
            self.app.close_draft(job_id=job, **auth)
            return fake_probe(fd)

        self.app = BlueVideoGateway(
            keys=KEYS, state=self.state, clock=lambda: NOW,
            upload_attestor=TrustedUploadAttestor(
                qa_root=self.root, rights_lookup=self.attestor._rights_lookup,
                probe_fn=closing_probe),
        )
        with self.assertRaisesRegex(PolicyFailure, "draft_missing_closed_or_foreign"):
            self.attest(job)
        self.assertIsNone(self.state.get_verified_evidence(
            tenant_id="tenant-a", job_id=job, now=NOW))

    def test_existing_verified_record_cannot_be_replaced(self):
        job = self.prepare()
        self.attest(job)
        changed_media = MEDIA.replace(b"fake", b"FAKE")
        (self.root / "tenant-a" / "0123456789abcdef.mp4").write_bytes(changed_media)
        self.approvals[("tenant-a", SOURCE)] = replace(
            self.approvals[("tenant-a", SOURCE)],
            source_sha256=hashlib.sha256(changed_media).hexdigest(),
        )
        with self.assertRaisesRegex(PolicyFailure, "conflicting_evidence"):
            self.attest(job)
        proof = self.state.get_verified_evidence(
            tenant_id="tenant-a", job_id=job, now=NOW)
        self.assertEqual(proof["source_sha256"], DIGEST)

    def test_durable_binding_survives_sqlite_restart_without_becoming_execution(self):
        job = self.prepare()
        self.attest(job)
        self.state.close()
        self.state = GatewayState(str(self.root / "state.sqlite"))
        restarted = self.state.get_verified_evidence(
            tenant_id="tenant-a", job_id=job, now=NOW)
        self.assertEqual(restarted["source_sha256"], DIGEST)
        self.assertEqual(self.state.get_for_tenant(
            "tenant-a", job, now=NOW)["state"], "prepared")
        self.assertIsNone(self.state.get_verified_evidence(
            tenant_id="tenant-b", job_id=job, now=NOW))

    def test_trusted_rights_store_outage_fails_closed(self):
        def unavailable(tenant, source):
            raise RuntimeError("sensitive store detail")
        self.app = BlueVideoGateway(
            keys=KEYS, state=self.state, clock=lambda: NOW,
            upload_attestor=TrustedUploadAttestor(
                qa_root=self.root, rights_lookup=unavailable, probe_fn=fake_probe),
        )
        job = self.prepare()
        with self.assertRaisesRegex(PolicyFailure, "rights_store_unavailable") as exc:
            self.attest(job)
        self.assertNotIn("sensitive store detail", str(exc.exception))
        self.assertIsNone(self.state.get_verified_evidence(
            tenant_id="tenant-a", job_id=job, now=NOW))

    def test_even_verified_evidence_never_authorizes_network_execution(self):
        job = self.prepare()
        self.attest(job)
        draft = self.state.get_for_tenant("tenant-a", job, now=NOW)
        with self.assertRaisesRegex(PolicyFailure, "network_execution_not_implemented"):
            self.app.prepare_upstream_task(draft, network_enabled=True)
        self.assertEqual(self.state.get_for_tenant(
            "tenant-a", job, now=NOW)["state"], "prepared")

    def test_attestation_api_has_no_public_asgi_route(self):
        from gateway.http_asgi import DRAFT_DETAIL, DRAFT_CLOSE
        path = "/internal/drafts/" + ("a" * 32) + "/attest"
        self.assertIsNone(DRAFT_DETAIL.fullmatch(path))
        self.assertIsNone(DRAFT_CLOSE.fullmatch(path))


if __name__ == "__main__":
    unittest.main()
