"""Offline signed QA rights-ledger and worker-blocking regression tests."""

from dataclasses import asdict, replace
import hashlib
import hmac
import json
import pathlib
import sqlite3
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gateway import BlueVideoGateway, GatewayState, PolicyFailure, VerificationKey
from gateway.core import sign_request
from gateway.evidence_binding import TrustedUploadAttestor
from gateway.media_evidence import RightsApproval
from gateway.qa_rights_ledger import (
    QASignedRightsLedger, RightsLedgerDenied, RightsLedgerUnavailable,
    _canonical_event,
)
from gateway.worker_handoff import OfflineWorkerHandoff, WorkerHandoffDenied

NOW = 1793539000
SOURCE = "upload:0123456789abcdef"
RIGHTS = "rights:qa-review-ref-0001"
TENANT = "tenant-a"
REVIEWER = "reviewer-approved-1"
KEY = b"review-key-separate-from-gateway--" + b"R" * 12
MEDIA = b"\x00\x00\x00\x18ftypisom" + b"ledger original synthetic sample " * 128
DIGEST = hashlib.sha256(MEDIA).hexdigest()


def sign(action, payload, key=KEY):
    return hmac.new(
        key, _canonical_event(action, payload), hashlib.sha256,
    ).hexdigest()


def probe(fd):
    import os
    assert os.fstat(fd).st_size == len(MEDIA)
    return {
        "format": {"duration": "120.25", "size": str(len(MEDIA)),
                   "format_name": "mov,mp4,m4a,3gp,3g2,mj2"},
        "streams": [
            {"codec_type": "video", "codec_name": "h264",
             "width": 1280, "height": 720}
        ],
    }


class RightsLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(pathlib.Path(self.tmp.name) / "rights.sqlite")
        self.ledger = QASignedRightsLedger(
            self.db, review_keys={REVIEWER: KEY}, clock=lambda: NOW)
        self.approval = RightsApproval(
            tenant_id=TENANT, source_ref=SOURCE,
            source_sha256=DIGEST, rights_ref=RIGHTS,
            approved_by=REVIEWER, approved_at=NOW - 30,
            valid_until=NOW + 400, processing_allowed=True,
        )

    def tearDown(self):
        self.ledger.close()
        self.tmp.cleanup()

    def register(self, record=None, key=KEY):
        item = record or self.approval
        self.ledger.approve(item, signature=sign(
            "approve", asdict(item), key))

    def revoke(self, *, tenant=TENANT, source=SOURCE,
               rights=RIGHTS, reviewer=REVIEWER, key=KEY, at=NOW):
        fields = {
            "tenant_id": tenant, "source_ref": source,
            "rights_ref": rights, "revoked_by": reviewer,
            "revoked_at": at,
        }
        self.ledger.revoke(
            tenant_id=tenant, source_ref=source,
            rights_ref=rights, reviewer=reviewer,
            revoked_at=at, signature=sign("revoke", fields, key),
        )

    def test_trusted_review_lookup_and_namespace(self):
        self.register()
        self.assertEqual(self.ledger.lookup(TENANT, SOURCE), self.approval)
        self.assertIsNone(self.ledger.lookup("tenant-b", SOURCE))
        self.assertIsNone(self.ledger.lookup(TENANT, "upload:someother000001"))

    def test_unsigned_client_boolean_cannot_create_rights(self):
        self.assertIsNone(self.ledger.lookup(TENANT, SOURCE))
        with self.assertRaisesRegex(RightsLedgerDenied, "review_signature_invalid"):
            self.ledger.approve(self.approval, signature="0" * 64)
        self.assertIsNone(self.ledger.lookup(TENANT, SOURCE))

    def test_forged_signature_and_altered_field_denied(self):
        bad = replace(self.approval, source_sha256="0" * 64)
        with self.assertRaises(RightsLedgerDenied):
            self.ledger.approve(
                bad, signature=sign("approve", asdict(self.approval)))
        with self.assertRaises(RightsLedgerDenied):
            self.register(key=b"attacker-key-pretending-to-be-reviewer" + b"0" * 7)

    def test_review_ttl_and_boolean_are_strict(self):
        for item in (
                replace(self.approval, approved_at=NOW - 301),
                replace(self.approval, valid_until=NOW - 1),
                replace(self.approval, valid_until=NOW + 40 * 86400),
                replace(self.approval, processing_allowed=1),
                replace(self.approval, source_ref="../data"),
                replace(self.approval, approved_by="other-reviewer"),
                replace(self.approval, approved_by=["untrusted-reviewer"])):
            with self.subTest(item=item), self.assertRaises(RightsLedgerDenied):
                self.register(item)

    def test_duplicate_review_cannot_replace_source_or_hash(self):
        self.register()
        with self.assertRaisesRegex(RightsLedgerDenied, "review_already_registered"):
            self.register()
        new = replace(self.approval, source_sha256="0" * 64)
        with self.assertRaisesRegex(RightsLedgerDenied, "review_already_registered"):
            self.register(new)
        self.assertEqual(self.ledger.lookup(TENANT, SOURCE), self.approval)

    def test_revocation_immediately_blocks_lookup(self):
        self.register()
        self.revoke()
        self.assertIsNone(self.ledger.lookup(TENANT, SOURCE))
        with self.assertRaises(RightsLedgerDenied):
            self.revoke()
        with self.assertRaises(RightsLedgerDenied):
            self.register()

    def test_wrong_tenant_or_rights_revocation_is_denied(self):
        self.register()
        with self.assertRaisesRegex(RightsLedgerDenied, "review_missing_or_revoked"):
            self.revoke(tenant="tenant-b")
        with self.assertRaisesRegex(RightsLedgerDenied, "review_missing_or_revoked"):
            self.revoke(rights="rights:other-record-001")
        self.assertIsNotNone(self.ledger.lookup(TENANT, SOURCE))

    def test_forged_revocation_and_replay_window_denied(self):
        self.register()
        with self.assertRaisesRegex(RightsLedgerDenied, "review_signature_invalid"):
            self.revoke(key=b"attack-key" * 5)
        with self.assertRaisesRegex(RightsLedgerDenied, "invalid_revocation"):
            self.revoke(at=NOW - 400)
        self.assertIsNotNone(self.ledger.lookup(TENANT, SOURCE))

    def test_persistent_revocation_survives_restart(self):
        self.register()
        self.revoke()
        self.ledger.close()
        self.ledger = QASignedRightsLedger(
            self.db, review_keys={REVIEWER: KEY}, clock=lambda: NOW)
        self.assertIsNone(self.ledger.lookup(TENANT, SOURCE))

    def test_tampered_approval_signature_fails_closed(self):
        self.register()
        with sqlite3.connect(self.db) as db:
            db.execute(
                """UPDATE signed_qa_rights SET source_sha256=?
                   WHERE tenant_id=? AND source_ref=?""",
                ("0" * 64, TENANT, SOURCE),
            )
        with self.assertRaisesRegex(RightsLedgerUnavailable, "qa_ledger_signature_invalid"):
            self.ledger.lookup(TENANT, SOURCE)

    def test_no_unknown_reviewer_can_write(self):
        self.register()
        fields = {
            "tenant_id": TENANT, "source_ref": SOURCE,
            "rights_ref": RIGHTS, "revoked_by": "untrusted-reviewer",
            "revoked_at": NOW,
        }
        with self.assertRaisesRegex(RightsLedgerDenied, "review_signature_invalid"):
            self.ledger.revoke(
                tenant_id=TENANT, source_ref=SOURCE, rights_ref=RIGHTS,
                reviewer="untrusted-reviewer", revoked_at=NOW,
                signature=sign("revoke", fields),
            )


class WorkerRevocationIntegrationTests(RightsLedgerTests):
    """Concrete QA SQLite rights lookup injected into gateway+worker gate."""

    def setUp(self):
        super().setUp()
        root = pathlib.Path(self.tmp.name)
        (root / TENANT).mkdir()
        (root / TENANT / "0123456789abcdef.mp4").write_bytes(MEDIA)
        self.state = GatewayState(str(root / "drafts.sqlite"))
        self.attestor = TrustedUploadAttestor(
            qa_root=root, rights_lookup=self.ledger.lookup, probe_fn=probe,
        )
        self.app = BlueVideoGateway(
            keys={"gateway-key": VerificationKey(TENANT, b"G" * 32)},
            state=self.state, clock=lambda: NOW,
            upload_attestor=self.attestor,
        )
        self.seq = 0
        self.worker = OfflineWorkerHandoff(
            state=self.state, attestor=self.attestor,
            object_head=lambda tenant, source, digest: {
                "tenant_id": tenant, "source_ref": source,
                "source_sha256": digest, "size_bytes": len(MEDIA),
                "version_id": "version:synthetic-private-001",
                "object_is_immutable": True, "private_acl_verified": True,
            },
        )

    def tearDown(self):
        self.state.close()
        super().tearDown()

    def auth(self, path, body=b""):
        self.seq += 1
        nonce = "RightsNonce" + str(self.seq).zfill(19)
        return {
            "key_id": "gateway-key", "timestamp": NOW, "nonce": nonce,
            "signature": sign_request(
                b"G" * 32, key_id="gateway-key", timestamp=NOW,
                nonce=nonce, method="POST", path=path, body=body,
            ),
        }

    def draft(self):
        body = json.dumps({
            "source_ref": SOURCE, "rights_confirmed": True,
            "consent_ref": RIGHTS, "source_duration_seconds": 120,
            "clip_length": "short", "idempotency_key": "rights_worker_001",
        }).encode()
        return self.app.prepare(
            body=body, **self.auth("/v1/drafts", body))["job_id"]

    def test_signed_rights_are_required_and_revocation_blocks_worker(self):
        job = self.draft()
        with self.assertRaises(PolicyFailure):
            self.app.attest_draft_offline(
                job_id=job,
                **self.auth("/internal/drafts/" + job + "/attest"),
            )
        self.register()
        got = self.app.attest_draft_offline(
            job_id=job,
            **self.auth("/internal/drafts/" + job + "/attest"),
        )
        self.assertEqual(got["execution"], "DISABLED")
        self.assertEqual(
            self.worker.check_offline(
                tenant_id=TENANT, job_id=job, now=NOW)["dispatch"], False)
        self.revoke()
        with self.assertRaisesRegex(WorkerHandoffDenied, "fresh_media_or_rights_denied"):
            self.worker.check_offline(tenant_id=TENANT, job_id=job, now=NOW)


if __name__ == "__main__":
    unittest.main()
