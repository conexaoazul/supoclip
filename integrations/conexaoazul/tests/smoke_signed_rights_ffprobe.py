#!/usr/bin/env python3
"""Opt-in synthetic QA smoke: FFprobe + signed local rights + revocation.

No real customer rights are proved; all identities, keys, bucket evidence and
media are synthetic. No S3 API call, Docker, queue, HTTP, egress, deployment,
SupoClip worker, Odoo or publication. Worker object head is a QA stub only.
"""

from dataclasses import asdict
import hashlib
import hmac
import json
import pathlib
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gateway import BlueVideoGateway, GatewayState, VerificationKey
from gateway.core import sign_request
from gateway.evidence_binding import TrustedUploadAttestor
from gateway.media_evidence import RightsApproval, ffprobe_fd
from gateway.qa_rights_ledger import QASignedRightsLedger, _canonical_event
from gateway.worker_handoff import OfflineWorkerHandoff, WorkerHandoffDenied

TENANT = "tenant-qa-signed"
SOURCE = "upload:syntheticsmoke001"
RIGHTS = "rights:synthetic-qa-test-001"
REVIEWER = "qa-reviewer-synthetic"
REVIEW_KEY = b"R" * 32
GATEWAY_KEY = b"G" * 32


def sig(action, values):
    return hmac.new(
        REVIEW_KEY, _canonical_event(action, values), hashlib.sha256,
    ).hexdigest()


def main():
    with tempfile.TemporaryDirectory(prefix="blue-video-signed-smoke-") as tmp:
        root = pathlib.Path(tmp)
        private = root / TENANT
        private.mkdir(mode=0o700)
        media = private / "syntheticsmoke001.mp4"
        command = [
            "ffmpeg", "-hide_banner", "-nostdin", "-v", "error", "-y",
            "-f", "lavfi", "-i", "color=c=black:s=128x128:r=10",
            "-t", "1", "-an", "-c:v", "libx264", "-preset", "ultrafast",
            "-pix_fmt", "yuv420p", "-movflags", "+faststart", str(media),
        ]
        try:
            result = subprocess.run(command, timeout=20, check=False,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired):
            print(json.dumps({"status": "BLOCKED", "reason": "ffmpeg_unavailable"}))
            return 2
        if result.returncode:
            print(json.dumps({"status": "BLOCKED", "reason": "synthetic_video_failed"}))
            return 2

        now = int(time.time())
        digest = hashlib.sha256(media.read_bytes()).hexdigest()
        review = RightsApproval(
            tenant_id=TENANT, source_ref=SOURCE, source_sha256=digest,
            rights_ref=RIGHTS, approved_by=REVIEWER, approved_at=now,
            valid_until=now + 120, processing_allowed=True,
        )
        ledger = QASignedRightsLedger(
            str(root / "qa-rights.sqlite"),
            review_keys={REVIEWER: REVIEW_KEY}, clock=lambda: now)
        state = GatewayState(str(root / "drafts.sqlite"))
        try:
            ledger.approve(review, signature=sig("approve", asdict(review)))
            attestor = TrustedUploadAttestor(
                qa_root=root, rights_lookup=ledger.lookup, probe_fn=ffprobe_fd)
            gateway = BlueVideoGateway(
                keys={"qa-key": VerificationKey(TENANT, GATEWAY_KEY)},
                state=state, clock=lambda: now, upload_attestor=attestor,
            )
            index = 0
            def auth(path, body=b""):
                nonlocal index
                index += 1
                nonce = "SignedSmokeNonce" + str(index).zfill(19)
                return {
                    "key_id": "qa-key", "nonce": nonce, "timestamp": now,
                    "signature": sign_request(
                        GATEWAY_KEY, key_id="qa-key", nonce=nonce,
                        timestamp=now, method="POST", path=path, body=body,
                    ),
                }
            body = json.dumps({
                "source_ref": SOURCE, "rights_confirmed": True,
                "consent_ref": RIGHTS, "clip_length": "short",
                "idempotency_key": "signed_smoke_0001",
                "source_duration_seconds": 1,
            }).encode("utf-8")
            job = gateway.prepare(
                body=body, **auth("/v1/drafts", body))["job_id"]
            first = gateway.attest_draft_offline(
                job_id=job, **auth("/internal/drafts/" + job + "/attest"))
            if first["execution"] != "DISABLED":
                raise AssertionError("unexpected_execution")
            # Explicit synthetic object-head: NOT proof of real S3 isolation.
            def fake_head(tenant, source, sha):
                return {
                    "tenant_id": tenant, "source_ref": source,
                    "source_sha256": sha, "size_bytes": media.stat().st_size,
                    "version_id": "version:synthetic-only-001",
                    "object_is_immutable": True, "private_acl_verified": True,
                }
            worker = OfflineWorkerHandoff(
                state=state, attestor=attestor, object_head=fake_head)
            checked = worker.check_offline(
                tenant_id=TENANT, job_id=job, now=now)
            if checked["dispatch"] is not False:
                raise AssertionError("unexpected_dispatch")
            revocation = {
                "tenant_id": TENANT, "source_ref": SOURCE,
                "rights_ref": RIGHTS, "revoked_by": REVIEWER,
                "revoked_at": now,
            }
            ledger.revoke(
                tenant_id=TENANT, source_ref=SOURCE,
                rights_ref=RIGHTS, reviewer=REVIEWER,
                revoked_at=now, signature=sig("revoke", revocation),
            )
            blocked = False
            try:
                worker.check_offline(
                    tenant_id=TENANT, job_id=job, now=now)
            except WorkerHandoffDenied:
                blocked = True
            if not blocked:
                raise AssertionError("revoked_media_was_accepted")
            print(json.dumps({
                "status": "PASS_SYNTHETIC_SIGNED_RIGHTS_ONLY",
                "real_ffprobe": True,
                "sha256": digest,
                "size_bytes": media.stat().st_size,
                "rights_revocation_blocks_recheck": blocked,
                "real_s3_acl_tested": False,
                "real_legal_approval_tested": False,
                "execution": "DISABLED",
                "dispatch": False,
                "deploy_executed": False,
            }, sort_keys=True))
            return 0
        finally:
            state.close()
            ledger.close()


if __name__ == "__main__":
    raise SystemExit(main())
