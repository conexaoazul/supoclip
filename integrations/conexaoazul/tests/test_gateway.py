"""Integration-independent, no-network BlueOps gateway regression suite."""

import importlib.util
import json
import pathlib
import sqlite3
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gateway import AuthFailure, BlueVideoGateway, GatewayState, PolicyFailure, VerificationKey
from gateway.core import normalize_source, sign_request


NOW = 1793539000
KEYS = {
    "key-a": VerificationKey("tenant-a", b"A" * 32),
    "key-b": VerificationKey("tenant-b", b"B" * 32),
    "disabled-key": VerificationKey("tenant-b", b"C" * 32, enabled=False),
}


def make_payload(**patch):
    data = {
        "source_ref": "https://youtu.be/ABCdef123_4",
        "rights_confirmed": True,
        "consent_ref": "rights:authorized-001",
        "clip_length": "short",
        "idempotency_key": "project_000001",
        "source_duration_seconds": 500,
    }
    data.update(patch)
    return json.dumps(data, sort_keys=True).encode()


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = str(pathlib.Path(self.temp.name) / "pilot.sqlite")
        self.state = GatewayState(self.db_path)
        self.app = BlueVideoGateway(keys=KEYS, state=self.state, clock=lambda: NOW)
        self.i = 0

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def auth(self, key_id="key-a", body=b"", method="POST", path="/v1/drafts",
             timestamp=NOW, nonce=None, secret=None, signature=None):
        self.i += 1
        nonce = nonce or ("qaNonce" + str(self.i).zfill(17))
        secret = secret or KEYS[key_id].secret
        signature = signature or sign_request(
            secret, key_id=key_id, timestamp=timestamp, nonce=nonce,
            method=method, path=path, body=body,
        )
        return dict(key_id=key_id, signature=signature, timestamp=timestamp,
                    nonce=nonce, body=body)

    def prepare(self, key_id="key-a", **patch):
        body = make_payload(**patch)
        return self.app.prepare(**self.auth(key_id=key_id, body=body))

    def test_one_prepared_metadata_only(self):
        created = self.prepare()
        self.assertEqual(created["state"], "prepared")
        self.assertTrue(created["created"])
        self.assertEqual(created["execution"], "DISABLED")
        self.assertNotIn("tenant_id", created)
        self.assertNotIn("source_ref", created)

    def test_replay_nonce_denied(self):
        auth = self.auth(body=make_payload())
        self.app.prepare(**auth)
        with self.assertRaises(AuthFailure):
            self.app.prepare(**auth)

    def test_tamper_detected(self):
        auth = self.auth(body=make_payload())
        auth["body"] = make_payload(source_duration_seconds=600)
        with self.assertRaises(AuthFailure):
            self.app.prepare(**auth)

    def test_signature_binds_method_and_path(self):
        auth = self.auth(body=make_payload(), method="GET")
        with self.assertRaises(AuthFailure):
            self.app.prepare(**auth)
        auth = self.auth(body=make_payload(), path="/v1/other")
        with self.assertRaises(AuthFailure):
            self.app.prepare(**auth)

    def test_wrong_secret_denied(self):
        a = self.auth(body=make_payload(), secret=b"X" * 32)
        with self.assertRaises(AuthFailure):
            self.app.prepare(**a)

    def test_expired_and_future_denied(self):
        for timestamp in (NOW - 301, NOW + 301):
            auth = self.auth(body=make_payload(), timestamp=timestamp)
            with self.subTest(timestamp=timestamp):
                with self.assertRaises(AuthFailure):
                    self.app.prepare(**auth)

    def test_missing_and_revoked_key_denied(self):
        auth = self.auth(key_id="disabled-key", body=make_payload())
        with self.assertRaises(AuthFailure):
            self.app.prepare(**auth)
        auth = self.auth(key_id="key-a", body=make_payload())
        auth["key_id"] = "unknown"
        with self.assertRaises(AuthFailure):
            self.app.prepare(**auth)

    def test_unknown_payload_field_denied_including_tenant(self):
        for patch in ({"tenant_id": "tenant-b"}, {"publish": True},
                      {"social_account_id": "any"}, {"url": "https://example.com"}):
            with self.subTest(patch=patch):
                with self.assertRaises(PolicyFailure):
                    self.prepare(**patch)

    def test_missing_rights_denied(self):
        for rights in (False, None, "true", 1):
            with self.subTest(rights=rights):
                with self.assertRaises(PolicyFailure):
                    self.prepare(rights_confirmed=rights)

    def test_unapproved_urls_denied(self):
        for src in (
            "https://127.0.0.1/watch?v=ABCdef123_4",
            "https://youtube.com.evil.test/watch?v=ABCdef123_4",
            "http://www.youtube.com/watch?v=ABCdef123_4",
            "https://www.youtube.com/redirect?url=http://169.254.169.254",
            "file:///etc/passwd",
            "https://www.youtube.com/watch?v=ABCdef123_4&redirect=evil",
            "https://youtu.be/ABCdef123_4?x=y",
            "https://a@youtube.com.evil.test/watch?v=ABCdef123_4",
            "https://www.youtube.com:444/watch?v=ABCdef123_4",
        ):
            with self.subTest(src=src):
                with self.assertRaises(PolicyFailure):
                    self.prepare(source_ref=src)

    def test_upload_reference_does_not_map_to_upstream(self):
        result = self.prepare(source_ref="upload:0123456789abcd")
        draft = self.state.get_for_tenant("tenant-a", result["job_id"])
        with self.assertRaises(PolicyFailure):
            self.app.prepare_upstream_task(draft)

    def test_upstream_plan_never_executes(self):
        result = self.prepare()
        draft = self.state.get_for_tenant("tenant-a", result["job_id"])
        plan = self.app.prepare_upstream_task(draft)
        self.assertEqual(plan["json"]["source"]["url"],
                         "https://www.youtube.com/watch?v=ABCdef123_4")
        self.assertEqual(plan["path"], "/tasks/")
        self.assertEqual(plan["execution"], "DISABLED")
        with self.assertRaises(PolicyFailure):
            self.app.prepare_upstream_task(draft, network_enabled=True)

    def test_same_tenant_same_key_same_intent_idempotent(self):
        a = self.prepare()
        b = self.prepare()
        self.assertEqual(a["job_id"], b["job_id"])
        self.assertFalse(b["created"])

    def test_idempotency_conflict_fail_closed(self):
        self.prepare()
        with self.assertRaisesRegex(PolicyFailure, "idempotency_conflict"):
            self.prepare(source_duration_seconds=900)

    def test_reused_key_across_tenants_not_same_job(self):
        a = self.prepare()
        b = self.prepare(key_id="key-b")
        self.assertNotEqual(a["job_id"], b["job_id"])

    def test_tenant_list_isolation(self):
        a = self.prepare()
        self.prepare(key_id="key-b")
        request = self.auth(key_id="key-a", method="GET", path="/v1/drafts")
        request.pop("body")
        listing = self.app.list_drafts(**request)
        self.assertEqual([v["job_id"] for v in listing], [a["job_id"]])
        self.assertIsNone(self.state.get_for_tenant("tenant-b", a["job_id"]))

    def test_pending_cap_three(self):
        for i in range(3):
            self.prepare(idempotency_key="number_" + str(i).zfill(8))
        with self.assertRaisesRegex(PolicyFailure, "tenant_queue_limit"):
            self.prepare(idempotency_key="number_00000099")
        self.assertEqual(len(self.state.list_for_tenant("tenant-a")), 3)

    def test_bad_duration_types_and_caps_denied(self):
        for duration in (0, 1801, -9, True, "30", None, 2.5):
            with self.subTest(duration=duration):
                with self.assertRaises(PolicyFailure):
                    self.prepare(source_duration_seconds=duration)

    def test_empty_queue_on_new_db(self):
        self.assertEqual(self.state.list_for_tenant("tenant-a"), [])

    def test_sqlite_durable_idempotency_after_restart(self):
        a = self.prepare()
        self.state.close()
        self.state = GatewayState(self.db_path)
        self.app = BlueVideoGateway(keys=KEYS, state=self.state, clock=lambda: NOW)
        b = self.prepare()
        self.assertEqual(a["job_id"], b["job_id"])
        self.assertFalse(b["created"])

    def test_sqlite_durable_nonce_after_restart(self):
        auth = self.auth(body=make_payload())
        self.app.prepare(**auth)
        self.state.close()
        self.state = GatewayState(self.db_path)
        self.app = BlueVideoGateway(keys=KEYS, state=self.state, clock=lambda: NOW)
        with self.assertRaises(AuthFailure):
            self.app.prepare(**auth)

    def test_duplicate_json_keys_denied(self):
        raw = (b'{"source_ref":"https://youtu.be/ABCdef123_4",'
               b'"rights_confirmed":true,"consent_ref":"rights:authorized-001",'
               b'"clip_length":"short","idempotency_key":"project_000001",'
               b'"source_duration_seconds":500,"rights_confirmed":true}')
        with self.assertRaises(PolicyFailure):
            self.app.prepare(**self.auth(body=raw))

    def test_publish_action_denied(self):
        for action in ("video_publish", "video_export", "external_communication",
                       "production_change", "video_delete"):
            with self.subTest(action=action):
                with self.assertRaises(PolicyFailure):
                    self.app.deny_unsafe_action(action)

    def test_weak_key_rejected(self):
        with self.assertRaises(ValueError):
            VerificationKey("tenant-a", b"short")

    def test_sqlite_duplicate_same_nonce_is_not_a_success(self):
        auth = self.auth(body=make_payload())
        self.app.prepare(**auth)
        with self.assertRaises(AuthFailure):
            self.app.prepare(**auth)

    def test_unauthenticated_cannot_list(self):
        request = self.auth(method="GET", path="/v1/drafts")
        request.pop("body")
        request["signature"] = "0" * 64
        with self.assertRaises(AuthFailure):
            self.app.list_drafts(**request)


if __name__ == "__main__":
    unittest.main()
