"""Offline S3 Object Lock/tenant-denial adapter contract tests (mock API)."""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import pathlib
import sys
import unittest
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gateway.qa_s3_object_proof import (
    QAAWSObjectProof, PrivateObjectProofDenied,
)

NOW = datetime(2026, 11, 2, 12, 0, tzinfo=timezone.utc)
TENANT = "tenant-a"
SOURCE = "upload:0123456789abcdef"
DIGEST = hashlib.sha256(b"synthetic object content").hexdigest()
VERSION = "vers:aws-qa-object-12345"
BUCKET = "blue-video-qa-secure"


class MockS3:
    def __init__(self):
        self.meta = SimpleNamespace(
            endpoint_url="https://s3.us-east-1.amazonaws.com")
        self.calls = []
        self.versioning = {"Status": "Enabled"}
        self.block = {"PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        }}
        self.public = {"PolicyStatus": {"IsPublic": False}}
        self.head = {
            "VersionId": VERSION, "ContentLength": 280,
            "ChecksumType": "FULL_OBJECT",
            "ChecksumSHA256": base64.b64encode(
                bytes.fromhex(DIGEST)).decode("ascii"),
            "ObjectLockMode": "COMPLIANCE",
            "ObjectLockRetainUntilDate": NOW + timedelta(days=1),
            "ServerSideEncryption": "AES256",
        }

    def get_bucket_versioning(self, *, Bucket):
        self.calls.append(("get_bucket_versioning", Bucket))
        return self.versioning

    def get_public_access_block(self, *, Bucket):
        self.calls.append(("get_public_access_block", Bucket))
        return self.block

    def get_bucket_policy_status(self, *, Bucket):
        self.calls.append(("get_bucket_policy_status", Bucket))
        return self.public

    def head_object(self, *, Bucket, Key, VersionId, ChecksumMode):
        self.calls.append(("head_object", Bucket, Key, VersionId, ChecksumMode))
        return self.head


class S3ObjectProofTests(unittest.TestCase):
    def setUp(self):
        self.s3 = MockS3()
        self.denied = True
        self.probe_calls = []
        def negative(**kwargs):
            self.probe_calls.append(kwargs)
            return self.denied
        self.adapter = QAAWSObjectProof(
            s3_client=self.s3, bucket=BUCKET,
            version_lookup=lambda *_args: VERSION,
            tenant_deny_probe=negative, clock=lambda: NOW,
        )

    def prove(self):
        return self.adapter(TENANT, SOURCE, DIGEST)

    def test_success_requires_full_checksum_lock_version_policy_denial(self):
        result = self.prove()
        self.assertEqual(result, {
            "tenant_id": TENANT, "source_ref": SOURCE,
            "source_sha256": DIGEST, "size_bytes": 280,
            "version_id": VERSION, "object_is_immutable": True,
            "private_acl_verified": True,
        })
        self.assertEqual(self.s3.calls[-1], (
            "head_object", BUCKET,
            "tenants/tenant-a/sha256/" + DIGEST + ".mp4",
            VERSION, "ENABLED",
        ))
        self.assertEqual(self.probe_calls[-1]["version_id"], VERSION)

    def test_host_must_be_real_aws_s3_https(self):
        for endpoint in (
            "http://s3.us-east-1.amazonaws.com",
            "https://s3.us-east-1.amazonaws.com.attacker.test",
            "https://storage.example.test",
            None,
        ):
            with self.subTest(endpoint=endpoint):
                self.s3.meta.endpoint_url = endpoint
                with self.assertRaises(ValueError):
                    QAAWSObjectProof(
                        s3_client=self.s3, bucket=BUCKET,
                        version_lookup=lambda *_: VERSION,
                        tenant_deny_probe=lambda **_: True,
                    )

    def test_versioning_or_public_policy_failure_denied(self):
        variants = [
            ("versioning", {"Status": "Suspended"}),
            ("versioning", {}),
            ("public", {"PolicyStatus": {"IsPublic": True}}),
            ("block", {"PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True, "BlockPublicPolicy": True,
                "RestrictPublicBuckets": False,
            }}),
        ]
        for attr, data in variants:
            with self.subTest(attr=attr, data=data):
                original = getattr(self.s3, attr)
                setattr(self.s3, attr, data)
                with self.assertRaisesRegex(
                        PrivateObjectProofDenied, "private_bucket_policy_unverified"):
                    self.prove()
                setattr(self.s3, attr, original)

    def test_weak_immutability_or_encryption_denied(self):
        for changes in (
            {"ObjectLockMode": "GOVERNANCE"},
            {"ObjectLockMode": None},
            {"ObjectLockRetainUntilDate": NOW + timedelta(minutes=1)},
            {"ObjectLockRetainUntilDate": NOW.replace(tzinfo=None)},
            {"ServerSideEncryption": None},
            {"VersionId": "another-version"},
            {"ContentLength": 1},
            {"ContentLength": True},
            {"ChecksumType": "COMPOSITE"},
        ):
            with self.subTest(changes=changes):
                original = dict(self.s3.head)
                self.s3.head.update(changes)
                with self.assertRaisesRegex(
                        PrivateObjectProofDenied, "immutable_version_unverified"):
                    self.prove()
                self.s3.head = original

    def test_checksum_missing_or_wrong_denied(self):
        originals = dict(self.s3.head)
        for checksum in (None, "not_base64@", base64.b64encode(b"0" * 32).decode()):
            with self.subTest(checksum=checksum):
                self.s3.head["ChecksumSHA256"] = checksum
                with self.assertRaises(PrivateObjectProofDenied):
                    self.prove()
        self.s3.head = originals

    def test_cross_tenant_deny_mandatory(self):
        self.denied = False
        with self.assertRaisesRegex(
                PrivateObjectProofDenied, "cross_tenant_isolation_unverified"):
            self.prove()

    def test_no_arbitrary_source_keys(self):
        for tenant, source, digest in (
            ("../tenant-b", SOURCE, DIGEST),
            (TENANT, "../private", DIGEST),
            (TENANT, SOURCE, "bad"),
            ("tenant-b", "https://evil.example/video", DIGEST),
        ):
            with self.subTest(tenant=tenant, source=source):
                with self.assertRaisesRegex(
                        PrivateObjectProofDenied, "invalid_object_context"):
                    self.adapter(tenant, source, digest)

    def test_invalid_version_registry_denied_without_s3(self):
        for version in (None, "", "null", "../unsafe", "a", "v+" * 10):
            with self.subTest(version=version):
                adapter = QAAWSObjectProof(
                    s3_client=self.s3, bucket=BUCKET,
                    version_lookup=lambda *_: version,
                    tenant_deny_probe=lambda **_: True,
                    clock=lambda: NOW,
                )
                before = len(self.s3.calls)
                with self.assertRaisesRegex(
                        PrivateObjectProofDenied, "trusted_version_required"):
                    adapter(TENANT, SOURCE, DIGEST)
                self.assertEqual(len(self.s3.calls), before)

    def test_network_and_acl_errors_fail_closed(self):
        class Offline(MockS3):
            def head_object(self, **kwargs):
                raise RuntimeError("private-secret-url")
        adapter = QAAWSObjectProof(
            s3_client=Offline(), bucket=BUCKET,
            version_lookup=lambda *_: VERSION,
            tenant_deny_probe=lambda **_: True,
            clock=lambda: NOW,
        )
        with self.assertRaises(PrivateObjectProofDenied) as exc:
            adapter(TENANT, SOURCE, DIGEST)
        self.assertNotIn("private-secret-url", str(exc.exception))

    def test_no_writes_or_dynamic_website_calls(self):
        self.prove()
        self.assertEqual(len(self.s3.calls), 4)
        self.assertEqual(
            {call[0] for call in self.s3.calls},
            {"get_bucket_versioning", "get_public_access_block",
             "get_bucket_policy_status", "head_object"},
        )


if __name__ == "__main__":
    unittest.main()
