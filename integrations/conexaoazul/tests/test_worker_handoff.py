"""No-network regression for pre-worker revalidation. Never dispatches media."""

from dataclasses import replace
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gateway import BlueVideoGateway, GatewayState, VerificationKey
from gateway.core import sign_request
from gateway.evidence_binding import TrustedUploadAttestor
from gateway.media_evidence import RightsApproval
from gateway.worker_handoff import OfflineWorkerHandoff, WorkerHandoffDenied

NOW = 1793539000
SOURCE = "upload:0123456789abcdef"
RIGHTS = "rights:qa-approved-00001"
MEDIA = b"\x00\x00\x00\x18ftypisom" + b"synthetic fake media for unit tests " * 100
SHA = hashlib.sha256(MEDIA).hexdigest()
KEYS = {"key-a": VerificationKey("tenant-a", b"A" * 32),
        "key-b": VerificationKey("tenant-b", b"B" * 32)}


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


class WorkerGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        (self.root / "tenant-a").mkdir()
        (self.root / "tenant-b").mkdir()
        self.media = self.root / "tenant-a" / "0123456789abcdef.mp4"
        self.media.write_bytes(MEDIA)
        self.state = GatewayState(str(self.root / "qa.sqlite"))
        self.rights = RightsApproval(
            tenant_id="tenant-a", source_ref=SOURCE, source_sha256=SHA,
            rights_ref=RIGHTS, approved_by="qa-reviewer-a",
            approved_at=NOW - 100, valid_until=NOW + 1000,
            processing_allowed=True,
        )
        self._nonce = 0
        self._head_calls = 0
        self.approvals = {("tenant-a", SOURCE): self.rights}

        def rights_lookup(tenant, source):
            return self.approvals.get((tenant, source))

        def object_head(tenant, source, digest):
            self._head_calls += 1
            return {
                "tenant_id": tenant, "source_ref": source,
                "source_sha256": digest, "size_bytes": len(MEDIA),
                "version_id": "version:qa-synthetic-0001",
                "object_is_immutable": True,
                "private_acl_verified": True,
            }

        self.object_head = object_head
        self.attestor = TrustedUploadAttestor(
            qa_root=self.root, rights_lookup=rights_lookup,
            probe_fn=fake_probe,
        )
        self.gateway = BlueVideoGateway(
            keys=KEYS, state=self.state, clock=lambda: NOW,
            upload_attestor=self.attestor,
        )
        self.gate = OfflineWorkerHandoff(
            state=self.state, attestor=self.attestor,
            object_head=self.object_head,
        )

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def signed(self, method, path, body=b""):
        self._nonce += 1
        nonce = "WorkerQA" + str(self._nonce).zfill(19)
        return {
            "key_id": "key-a", "nonce": nonce, "timestamp": NOW,
            "signature": sign_request(
                KEYS["key-a"].secret, key_id="key-a", nonce=nonce,
                timestamp=NOW, method=method, path=path, body=body,
            ),
        }

    def draft(self, verified=True):
        body = json.dumps({
            "source_ref": SOURCE, "rights_confirmed": True,
            "consent_ref": RIGHTS, "clip_length": "short",
            "idempotency_key": "worker_qa_intent_001",
            "source_duration_seconds": 120,
        }).encode()
        result = self.gateway.prepare(
            body=body, **self.signed("POST", "/v1/drafts", body))
        job_id = result["job_id"]
        if verified:
            self.gateway.attest_draft_offline(
                job_id=job_id,
                **self.signed("POST", "/internal/drafts/" + job_id + "/attest"),
            )
        return job_id

    def check(self, job, tenant="tenant-a"):
        return self.gate.check_offline(
            tenant_id=tenant, job_id=job, now=NOW)

    def test_matching_snapshots_never_dispatch(self):
        job = self.draft()
        got = self.check(job)
        self.assertEqual(got["rehearsal"], "CHECKS_MATCHED")
        self.assertEqual(got["execution"], "DISABLED")
        self.assertIs(got["dispatch"], False)
        self.assertIs(got["publish"], False)
        self.assertEqual(got["proof_snapshot_sha256"], SHA)
        self.assertEqual(self._head_calls, 1)

    def test_draft_not_attested_is_denied_without_head(self):
        job = self.draft(verified=False)
        with self.assertRaisesRegex(WorkerHandoffDenied, "missing_initial_attestation"):
            self.check(job)
        self.assertEqual(self._head_calls, 0)

    def test_other_tenant_cannot_recheck(self):
        job = self.draft()
        with self.assertRaisesRegex(WorkerHandoffDenied, "draft_closed_or_foreign"):
            self.check(job, tenant="tenant-b")

    def test_revoked_rights_denied_before_storage(self):
        job = self.draft()
        self.approvals[("tenant-a", SOURCE)] = replace(
            self.rights, processing_allowed=False,
        )
        with self.assertRaisesRegex(WorkerHandoffDenied, "fresh_media_or_rights_denied"):
            self.check(job)
        self.assertEqual(self._head_calls, 0)

    def test_media_modified_since_attestation_denied(self):
        job = self.draft()
        self.media.write_bytes(MEDIA.replace(b"synthetic", b"SYNTHETIC"))
        with self.assertRaisesRegex(WorkerHandoffDenied, "fresh_media_or_rights_denied"):
            self.check(job)

    def test_rights_store_outage_denied(self):
        job = self.draft()
        def broken(_tenant, _source):
            raise RuntimeError("secret_value_should_not_leak")
        self.gate = OfflineWorkerHandoff(
            state=self.state,
            attestor=TrustedUploadAttestor(
                qa_root=self.root, rights_lookup=broken, probe_fn=fake_probe),
            object_head=self.object_head,
        )
        with self.assertRaises(WorkerHandoffDenied) as exc:
            self.check(job)
        self.assertNotIn("secret_value", str(exc.exception))

    def test_object_store_outage_denied(self):
        job = self.draft()
        def broken(_tenant, _source, _digest):
            raise OSError("secret object path")
        self.gate = OfflineWorkerHandoff(
            state=self.state, attestor=self.attestor, object_head=broken)
        with self.assertRaisesRegex(WorkerHandoffDenied, "private_object_store_unavailable"):
            self.check(job)

    def test_fake_immutable_or_acl_or_tenant_denied(self):
        job = self.draft()
        for change in (
            {"object_is_immutable": False},
            {"private_acl_verified": False},
            {"tenant_id": "tenant-b"},
            {"source_sha256": "0" * 64},
            {"size_bytes": len(MEDIA) + 2},
            {"version_id": ""},
            {"version_id": "../etc/passwd"},
        ):
            def wrong(tenant, source, digest):
                data = self.object_head(tenant, source, digest)
                data.update(change)
                return data
            gate = OfflineWorkerHandoff(
                state=self.state, attestor=self.attestor, object_head=wrong)
            with self.subTest(change=change), self.assertRaises(
                    WorkerHandoffDenied):
                gate.check_offline(tenant_id="tenant-a", job_id=job, now=NOW)

    def test_object_extra_untrusted_fields_denied(self):
        job = self.draft()
        def wrong(tenant, source, digest):
            data = self.object_head(tenant, source, digest)
            data["public_url"] = "https://evil.example"
            return data
        gate = OfflineWorkerHandoff(
            state=self.state, attestor=self.attestor, object_head=wrong)
        with self.assertRaisesRegex(WorkerHandoffDenied, "object_proof_invalid"):
            gate.check_offline(tenant_id="tenant-a", job_id=job, now=NOW)

    def test_close_during_storage_lookup_denied(self):
        job = self.draft()
        def closing(tenant, source, digest):
            self.gateway.close_draft(
                job_id=job, **self.signed(
                    "POST", "/v1/drafts/" + job + "/close"))
            return self.object_head(tenant, source, digest)
        gate = OfflineWorkerHandoff(
            state=self.state, attestor=self.attestor, object_head=closing)
        with self.assertRaisesRegex(WorkerHandoffDenied, "draft_closed_during_recheck"):
            gate.check_offline(tenant_id="tenant-a", job_id=job, now=NOW)

    def test_expired_draft_denied(self):
        job = self.draft()
        with self.assertRaisesRegex(WorkerHandoffDenied, "draft_closed_or_foreign"):
            self.gate.check_offline(
                tenant_id="tenant-a", job_id=job, now=NOW + 86401)

    def test_no_source_claim_controls_worker(self):
        job = self.draft()
        with self.assertRaisesRegex(WorkerHandoffDenied, "invalid_context"):
            self.gate.check_offline(
                tenant_id="../tenant-a", job_id=job, now=NOW)
        with self.assertRaisesRegex(WorkerHandoffDenied, "invalid_context"):
            self.gate.check_offline(
                tenant_id="tenant-a", job_id="z" * 32, now=NOW)
        with self.assertRaisesRegex(WorkerHandoffDenied, "invalid_context"):
            self.gate.check_offline(
                tenant_id="tenant-a", job_id=job, now=True)


if __name__ == "__main__":
    unittest.main()
