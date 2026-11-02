"""Mock AWS-identity and remote-HEAD negative tests; no cloud calls."""

import hashlib
import pathlib
import sys
import unittest
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gateway.qa_tenant_deny_probe import (
    QAAwsCrossTenantHeadDeny, QATenantIsolationDenied,
)

ACCOUNT = "123456789012"
ARN = "arn:aws:sts::123456789012:assumed-role/qa-video-tenant-b/session-1"
SHA = hashlib.sha256(b"purely synthetic qa").hexdigest()
PREFIX = "tenants/tenant-a/sha256/" + SHA + ".mp4"
VERSION = "version:synthetic-qa-001"


class FakeS3Error(Exception):
    def __init__(self, code, http_code):
        super().__init__("s3 diagnostic secret must not leak")
        self.response = {
            "Error": {"Code": code},
            "ResponseMetadata": {"HTTPStatusCode": http_code},
        }


class FakeSession:
    def __init__(self):
        self.arn = ARN
        self.account = ACCOUNT
        self.error = FakeS3Error("AccessDenied", 403)
        self.sts_calls = 0
        self.s3_calls = []
        self.client_names = []

    def client(self, service):
        self.client_names.append(service)
        if service not in ("s3", "sts"):
            raise AssertionError(service)
        return self

    def get_caller_identity(self):
        self.sts_calls += 1
        return {"Account": self.account, "Arn": self.arn}

    def head_object(self, **kwargs):
        self.s3_calls.append(kwargs)
        if self.error:
            raise self.error
        return {"ContentLength": 1}


class NegativeIAMTests(unittest.TestCase):
    def setUp(self):
        self.session = FakeSession()
        self.probe = QAAwsCrossTenantHeadDeny(
            session=self.session, foreign_tenant_id="tenant-b",
            expected_account_id=ACCOUNT, expected_assumed_role_arn=ARN,
        )

    def check(self, **overrides):
        values = dict(tenant_id="tenant-a", bucket="video-qa-private",
                      key=PREFIX, version_id=VERSION)
        values.update(overrides)
        return self.probe(**values)

    def test_real_shape_access_denied_for_foreign_identity_accepted(self):
        self.assertIs(self.check(), True)
        self.assertEqual(self.session.client_names, ["sts", "s3"])
        self.assertEqual(self.session.sts_calls, 1)
        self.assertEqual(self.session.s3_calls, [{
            "Bucket": "video-qa-private",
            "Key": PREFIX,
            "VersionId": VERSION,
        }])

    def test_owner_identity_not_foreign_rejected_before_network(self):
        with self.assertRaisesRegex(
                QATenantIsolationDenied, "invalid_cross_tenant_context"):
            self.check(tenant_id="tenant-b")
        self.assertEqual(self.session.sts_calls, 0)

    def test_wrong_sts_principal_or_account_rejected_before_head(self):
        for account, arn in (
            ("111111111111", ARN),
            (ACCOUNT, ARN.replace("qa-video-tenant-b", "some-other-role")),
            (ACCOUNT, ""),
        ):
            self.session.account = account
            self.session.arn = arn
            with self.subTest(account=account, arn=arn):
                with self.assertRaisesRegex(
                        QATenantIsolationDenied, "foreign_identity_mismatch"):
                    self.check()
                self.assertEqual(self.session.s3_calls, [])
        self.assertEqual(self.session.sts_calls, 3)

    def test_wrong_key_namespace_rejected_before_network(self):
        for key in (
            "../etc/passwd", "tenants/tenant-b/sha256/" + SHA + ".mp4",
            "tenants/tenant-a/sha256/" + SHA + ".jpg",
            "tenants/tenant-a/sha256/" + "00" + ".mp4",
            "tenants/tenant-a/sha256/" + SHA + ".mp4/escape",
        ):
            with self.subTest(key=key), self.assertRaisesRegex(
                    QATenantIsolationDenied, "invalid_object_namespace"):
                self.check(key=key)
        self.assertEqual(self.session.sts_calls, 0)

    def test_wrong_codes_do_not_masquerade_as_denial(self):
        for code, status in (
            ("NoSuchKey", 404),
            ("AccessDenied", 404),
            ("NoSuchVersion", 404),
            ("InvalidAccessKeyId", 403),
            ("SignatureDoesNotMatch", 403),
            ("AccessDenied", 500),
        ):
            self.session.error = FakeS3Error(code, status)
            with self.subTest(code=code, status=status):
                with self.assertRaisesRegex(
                        QATenantIsolationDenied,
                        "foreign_head_not_proven_denied") as err:
                    self.check()
                self.assertNotIn("s3 diagnostic secret", str(err.exception))

    def test_successful_foreign_head_is_security_failure(self):
        self.session.error = None
        with self.assertRaisesRegex(
                QATenantIsolationDenied, "cross_tenant_head_unexpectedly_allowed"):
            self.check()

    def test_unavailable_sts_denied(self):
        class Outage(FakeSession):
            def get_caller_identity(self):
                raise TimeoutError("secret internal host")
        s = Outage()
        p = QAAwsCrossTenantHeadDeny(
            session=s, foreign_tenant_id="tenant-b",
            expected_account_id=ACCOUNT, expected_assumed_role_arn=ARN)
        with self.assertRaisesRegex(
                QATenantIsolationDenied, "foreign_identity_unavailable") as error:
            p(tenant_id="tenant-a", bucket="video-qa-private",
              key=PREFIX, version_id=VERSION)
        self.assertNotIn("secret internal host", str(error.exception))

    def test_bad_config_fails_fast(self):
        for session, foreign, account, arn in (
            (None, "tenant-b", ACCOUNT, ARN),
            (self.session, "bad/tenant", ACCOUNT, ARN),
            (self.session, "tenant-b", "bad", ARN),
            (self.session, "tenant-b", ACCOUNT,
             "arn:aws:sts::000000000000:assumed-role/test/session"),
        ):
            with self.subTest(foreign=foreign, account=account), self.assertRaises(
                    ValueError):
                QAAwsCrossTenantHeadDeny(
                    session=session, foreign_tenant_id=foreign,
                    expected_account_id=account,
                    expected_assumed_role_arn=arn)

    def test_cross_tenant_bad_version_denied_before_network(self):
        with self.assertRaisesRegex(
                QATenantIsolationDenied, "invalid_cross_tenant_context"):
            self.check(version_id="../secret")

    def test_bucket_not_pretended_public(self):
        with self.assertRaisesRegex(
                QATenantIsolationDenied, "invalid_cross_tenant_context"):
            self.check(bucket="Video_Private_Bucket")


if __name__ == "__main__":
    unittest.main()
