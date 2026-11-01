"""Offline QA-only media evidence regression: no actual ffprobe or remote calls."""

import hashlib
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gateway.media_evidence import (EvidenceDenied, RightsApproval,
                                    attest_private_upload)

NOW = 1793550000
VIDEO = b"\x00\x00\x00\x18ftypisom" + b"QA-only synthetic bytes; not a real video " * 8
REF = "upload:0123456789abcdef"
SHA = hashlib.sha256(VIDEO).hexdigest()


def fake_probe(fd):
    # This fixture simulates a pinned ffprobe; no video or machine is tested.
    assert os.fstat(fd).st_size == len(VIDEO)
    return {
        "format": {"duration": "120.25", "size": str(len(VIDEO)),
                   "format_name": "mov,mp4,m4a,3gp,3g2,mj2"},
        "streams": [
            {"codec_type": "video", "codec_name": "h264",
             "width": 1920, "height": 1080},
            {"codec_type": "audio", "codec_name": "aac"},
        ],
    }


class SourceEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.a = self.root / "tenant-a"
        self.b = self.root / "tenant-b"
        self.a.mkdir()
        self.b.mkdir()
        self.file = self.a / "0123456789abcdef.mp4"
        self.file.write_bytes(VIDEO)
        self.rights = RightsApproval(
            tenant_id="tenant-a", source_ref=REF, source_sha256=SHA,
            rights_ref="rights:qa-approval-0001", approved_by="qa-reviewer-01",
            approved_at=NOW - 200, valid_until=NOW + 1000,
            processing_allowed=True,
        )

    def tearDown(self):
        self.temp.cleanup()

    def attest(self, **changes):
        args = {
            "qa_root": self.root, "verified_tenant": "tenant-a",
            "upload_ref": REF, "claimed_duration_seconds": 120,
            "rights_record": self.rights, "now": NOW, "probe_fn": fake_probe,
        }
        args.update(changes)
        return attest_private_upload(**args)

    def test_approved_fixture_generates_nonexecuting_metadata(self):
        item = self.attest()
        self.assertEqual(item["source_sha256"], SHA)
        self.assertEqual(item["size_bytes"], len(VIDEO))
        self.assertEqual(item["duration_seconds"], 120.25)
        self.assertEqual(item["rights_ref"], "rights:qa-approval-0001")
        self.assertEqual(item["tenant_id"], "tenant-a")
        self.assertEqual(item["execution"], "DISABLED")
        self.assertNotIn("filesystem_path", item)
        self.assertNotIn("media_bytes", item)

    def test_probe_required_not_silently_assumed(self):
        with self.assertRaisesRegex(EvidenceDenied, "media_probe_not_configured"):
            self.attest(probe_fn=None)

    def test_forbid_unscoped_url_and_path(self):
        for value in ("https://www.youtube.com/watch?v=ABCdef123_4",
                      "upload:../../etc/passwd",
                      "../something.mp4", "file:///etc/passwd",
                      "upload:bad/thing", "", None):
            with self.subTest(value=value):
                with self.assertRaises(EvidenceDenied):
                    self.attest(upload_ref=value)

    def test_no_cross_tenant_read(self):
        with self.assertRaises(EvidenceDenied):
            self.attest(verified_tenant="tenant-b")
        self.assertFalse((self.b / self.file.name).exists())

    def test_bypass_tenant_path_denied(self):
        for tenant in ("../tenant-a", ".", "other/path", "", "tenant-a/../tenant-b"):
            with self.subTest(tenant=tenant):
                with self.assertRaises(EvidenceDenied):
                    self.attest(verified_tenant=tenant)

    def test_rights_not_accepted_from_caller_boolean(self):
        for record in (True, {"rights_confirmed": True}, None, False):
            with self.subTest(record=record), self.assertRaises(EvidenceDenied):
                self.attest(rights_record=record)

    def test_unapproved_or_expired_record_denied(self):
        from dataclasses import replace
        for record in (
            replace(self.rights, processing_allowed=False),
            replace(self.rights, valid_until=NOW - 1),
            replace(self.rights, approved_at=NOW + 1),
            replace(self.rights, rights_ref=""),
            replace(self.rights, approved_by=""),
            replace(self.rights, tenant_id="tenant-b"),
            replace(self.rights, source_ref="upload:differentfile01"),
        ):
            with self.subTest(record=record):
                with self.assertRaises(EvidenceDenied):
                    self.attest(rights_record=record)

    def test_hash_mismatch_denied_before_probe(self):
        from dataclasses import replace
        bad = replace(self.rights, source_sha256="0" * 64)
        called = []
        def probe(fd):
            called.append(fd)
            return fake_probe(fd)
        with self.assertRaisesRegex(EvidenceDenied, "rights_approval_missing"):
            self.attest(rights_record=bad, probe_fn=probe)
        self.assertEqual(called, [])

    def test_traversal_symlink_and_hardlink_rejected(self):
        link = self.a / "1122334455667788.mp4"
        os.symlink(self.file, link)
        ref = "upload:1122334455667788"
        from dataclasses import replace
        with self.assertRaises(EvidenceDenied):
            self.attest(upload_ref=ref,
                        rights_record=replace(self.rights, source_ref=ref))
        os.unlink(link)
        os.link(self.file, link)
        with self.assertRaises(EvidenceDenied):
            self.attest()
        os.unlink(link)

    def test_invalid_file_magic_and_size(self):
        self.file.write_bytes(b"not a video")
        with self.assertRaises(EvidenceDenied):
            self.attest()
        self.file.write_bytes(b"\x00" * 100)
        with self.assertRaises(EvidenceDenied):
            self.attest()

    def test_claim_duration_must_match_probed_within_two_seconds(self):
        for claimed in (0, 125, 1801, True, "120"):
            with self.subTest(claimed=claimed), self.assertRaises(EvidenceDenied):
                self.attest(claimed_duration_seconds=claimed)

    def test_probe_duration_is_independently_bounded(self):
        def invalid(fd):
            v = fake_probe(fd)
            v["format"]["duration"] = "1800.00001"
            return v
        with self.assertRaisesRegex(EvidenceDenied, "invalid_duration"):
            self.attest(probe_fn=invalid)

    def test_invalid_probe_no_video_denied(self):
        def invalid(fd):
            return {"format": {"format_name": "mov,mp4,m4a,3gp,3g2,mj2",
                               "duration": "120.25"},
                    "streams": [{"codec_type": "audio", "codec_name": "aac"}]}
        with self.assertRaisesRegex(EvidenceDenied, "invalid_video_stream_count"):
            self.attest(probe_fn=invalid)

    def test_non_mp4_and_unsupported_codec_denied(self):
        for format_name, codec in (("matroska,webm", "h264"),
                                   ("mov,mp4,m4a,3gp,3g2,mj2", "vp9")):
            def invalid(fd):
                d = fake_probe(fd)
                d["format"]["format_name"] = format_name
                d["streams"][0]["codec_name"] = codec
                return d
            with self.subTest(format_name=format_name, codec=codec):
                with self.assertRaises(EvidenceDenied):
                    self.attest(probe_fn=invalid)

    def test_streams_untrusted_rejected(self):
        def embedded(fd):
            d = fake_probe(fd)
            d["streams"].append({"codec_type": "attachment", "codec_name": "bin"})
            return d
        with self.assertRaisesRegex(EvidenceDenied, "unexpected_stream"):
            self.attest(probe_fn=embedded)

    def test_invalid_dimensions_rejected(self):
        def huge(fd):
            d = fake_probe(fd)
            d["streams"][0]["width"] = 8000
            return d
        with self.assertRaisesRegex(EvidenceDenied, "invalid_dimensions"):
            self.attest(probe_fn=huge)

    def test_probe_error_is_not_approval(self):
        def failed(fd):
            raise EvidenceDenied("media_probe_failed")
        with self.assertRaisesRegex(EvidenceDenied, "media_probe_failed"):
            self.attest(probe_fn=failed)


if __name__ == "__main__":
    unittest.main()
