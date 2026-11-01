#!/usr/bin/env python3
"""Optional manual ffprobe smoke using locally generated synthetic QA media.

This is NOT a legal-rights clearance, real customer media test, container
sandbox validation, production worker test, or proof of object storage ACL.
Creates a tiny synthetic H.264 MP4 under a temporary per-tenant directory.
No network calls, uploads, queues, Odoo changes, social sends or deploy.
"""

import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gateway.media_evidence import (
    EvidenceDenied, RightsApproval, attest_private_upload, ffprobe_fd,
)


def main():
    with tempfile.TemporaryDirectory(prefix="blue-video-synthetic-") as tmp:
        qa_root = pathlib.Path(tmp)
        tenant = "tenant-qa-smoke"
        sub = qa_root / tenant
        sub.mkdir(mode=0o700)
        source_ref = "upload:syntheticsmoke001"
        path = sub / "syntheticsmoke001.mp4"
        # Fixed, no user strings interpolated into executable command.
        args = [
            "ffmpeg", "-hide_banner", "-nostdin", "-v", "error", "-y",
            "-f", "lavfi", "-i", "color=c=black:s=128x128:r=10",
            "-t", "1", "-an", "-c:v", "libx264", "-preset", "ultrafast",
            "-pix_fmt", "yuv420p", "-movflags", "+faststart",
            str(path),
        ]
        try:
            built = subprocess.run(
                args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, check=False, timeout=20,
            )
        except (OSError, subprocess.TimeoutExpired):
            print(json.dumps({"status":"BLOCKED", "reason":"ffmpeg_unavailable"}))
            return 2
        if built.returncode or not path.is_file():
            print(json.dumps({"status":"BLOCKED", "reason":"synthetic_media_build_failed"}))
            return 2
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        now = int(time.time())
        approval = RightsApproval(
            tenant_id=tenant, source_ref=source_ref,
            source_sha256=digest, rights_ref="rights:synthetic-smoke-001",
            approved_by="qa-synthetic-only",
            approved_at=now - 30, valid_until=now + 120,
            processing_allowed=True,
        )
        try:
            result = attest_private_upload(
                qa_root=qa_root, verified_tenant=tenant,
                upload_ref=source_ref, claimed_duration_seconds=1,
                rights_record=approval, now=now, probe_fn=ffprobe_fd,
            )
        except EvidenceDenied as exc:
            print(json.dumps({
                "status":"BLOCKED", "reason":str(exc),
                "execution":"DISABLED",
            }))
            return 2
        assert result["source_sha256"] == digest
        assert result["codec"] == "h264"
        assert result["duration_seconds"] > 0
        assert result["execution"] == "DISABLED"
        print(json.dumps({
            "status":"PASS_SYNTHETIC_ONLY",
            "codec":result["codec"],
            "duration_seconds":result["duration_seconds"],
            "size_bytes":result["size_bytes"],
            "sha256":digest,
            "tenant_isolation":"NOT_REAL_STORAGE_TESTED",
            "rights":"SYNTHETIC_FIXTURE_NOT_LEGAL_EVIDENCE",
            "execution":"DISABLED",
            "deploy_executed":False,
        }, sort_keys=True))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
