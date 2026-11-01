"""In-memory ASGI transport tests; no sockets, server, HTTP clients or secrets."""

import asyncio
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gateway import BlueVideoGateway, GatewayState, VerificationKey
from gateway.core import sign_request
from gateway.http_asgi import create_app


TIME = 1793539000
KEYS = {
    "key-a": VerificationKey("tenant-a", b"A" * 32),
    "key-b": VerificationKey("tenant-b", b"B" * 32),
}


def payload(**changes):
    p = {
        "source_ref": "https://youtu.be/ABCdef123_4",
        "rights_confirmed": True,
        "consent_ref": "rights:local-test-001",
        "clip_length": "short",
        "idempotency_key": "example_00000001",
        "source_duration_seconds": 500,
    }
    p.update(changes)
    return json.dumps(p, sort_keys=True).encode()


class HTTPAdapterTest(unittest.TestCase):
    def setUp(self):
        self.state = GatewayState()
        self.app = create_app(BlueVideoGateway(keys=KEYS, state=self.state, clock=lambda: TIME))
        self.n = 0

    def tearDown(self):
        self.state.close()

    def request(self, method="POST", path="/v1/drafts", body=None, key_id="key-a",
                scheme="https", path_in_sig=None, method_in_sig=None,
                signature=None, headers=None, query=b"", raw_path=None):
        self.n += 1
        if body is None:
            body = payload() if method == "POST" else b""
        nonce = "QANONCE" + str(self.n).zfill(20)
        sig = signature or sign_request(
            KEYS[key_id].secret,
            key_id=key_id,
            timestamp=TIME,
            nonce=nonce,
            method=method_in_sig or method,
            path=path_in_sig or path,
            body=body,
        )
        hdrs = [
            (b"x-blue-key-id", key_id.encode()),
            (b"x-blue-timestamp", str(TIME).encode()),
            (b"x-blue-nonce", nonce.encode()),
            (b"x-blue-signature", sig.encode()),
        ]
        if method == "POST":
            hdrs.append((b"content-type", b"application/json"))
        if headers:
            hdrs.extend(headers)
        events = [
            {"type": "http.request", "body": body, "more_body": False},
        ]

        async def receive():
            return events.pop(0)

        messages = []

        async def send(msg):
            messages.append(msg)

        scope = {
            "type": "http", "scheme": scheme, "method": method,
            "path": path, "raw_path": raw_path if raw_path is not None else path.encode(),
            "query_string": query, "headers": hdrs,
        }
        asyncio.run(self.app(scope, receive, send))
        status = messages[0]["status"]
        data = json.loads(messages[1]["body"].decode())
        response_headers = dict(messages[0]["headers"])
        return status, data, response_headers, scope

    def test_create_metadata_only(self):
        status, data, headers, _ = self.request()
        self.assertEqual(status, 201)
        self.assertEqual(data["execution"], "DISABLED")
        self.assertEqual(data["state"], "prepared")
        self.assertTrue(data["created"])
        self.assertNotIn("tenant_id", data)
        self.assertNotIn("source_ref", data)
        self.assertEqual(headers[b"cache-control"], b"no-store")
        self.assertEqual(headers[b"x-content-type-options"], b"nosniff")

    def test_idempotent_same_intent(self):
        s1, r1, _, _ = self.request()
        s2, r2, _, _ = self.request()
        self.assertEqual((s1, s2), (201, 200))
        self.assertEqual(r1["job_id"], r2["job_id"])
        self.assertFalse(r2["created"])

    def test_conflicting_key_gives_409(self):
        self.request()
        s, data, _, _ = self.request(body=payload(source_duration_seconds=600))
        self.assertEqual(s, 409)
        self.assertEqual(data["error"], "idempotency_conflict")

    def test_quota_429(self):
        for n in range(3):
            s, _, _, _ = self.request(body=payload(idempotency_key="draft_" + str(n).zfill(9)))
            self.assertEqual(s, 201)
        status, d, _, _ = self.request(body=payload(idempotency_key="draft_123456789"))
        self.assertEqual(status, 429)
        self.assertEqual(d["error"], "queue_limit")

    def test_private_list_and_detail(self):
        _, created, _, _ = self.request(key_id="key-a")
        _, other, _, _ = self.request(key_id="key-b")
        a_status, a_list, _, _ = self.request(method="GET", key_id="key-a")
        b_status, b_list, _, _ = self.request(method="GET", key_id="key-b")
        self.assertEqual((a_status, b_status), (200, 200))
        self.assertEqual([row["job_id"] for row in a_list["drafts"]], [created["job_id"]])
        self.assertEqual([row["job_id"] for row in b_list["drafts"]], [other["job_id"]])
        path = "/v1/drafts/" + created["job_id"]
        s, result, _, _ = self.request(method="GET", path=path, key_id="key-a")
        self.assertEqual(s, 200)
        self.assertEqual(result["job_id"], created["job_id"])
        s, result, _, _ = self.request(method="GET", path=path, key_id="key-b")
        self.assertEqual(s, 404)
        self.assertEqual(result["error"], "not_found")

    def test_tls_required_even_if_client_spoofs_forwarded_header(self):
        s, d, _, _ = self.request(
            scheme="http", headers=[(b"x-forwarded-proto", b"https")])
        self.assertEqual(s, 426)
        self.assertEqual(d["error"], "tls_required")
        self.assertEqual(len(self.state.list_for_tenant("tenant-a")), 0)

    def test_method_and_path_binding(self):
        s, d, _, _ = self.request(method_in_sig="GET")
        self.assertEqual((s, d["error"]), (401, "unauthorized"))
        s, d, _, _ = self.request(path_in_sig="/v1/other")
        self.assertEqual((s, d["error"]), (401, "unauthorized"))

    def test_invalid_signature_does_not_echo_secret(self):
        s, d, _, _ = self.request(signature="0" * 64)
        self.assertEqual((s, d), (401, {"error": "unauthorized"}))

    def test_duplicate_auth_header_denied(self):
        s, d, _, _ = self.request(headers=[(b"x-blue-key-id", b"key-b")])
        self.assertEqual((s, d["error"]), (400, "invalid_request"))

    def test_non_json_content_type_denied(self):
        s, d, _, _ = self.request(headers=[(b"content-type", b"text/plain")])
        self.assertEqual((s, d["error"]), (400, "invalid_request"))

    def test_get_body_denied(self):
        s, d, _, _ = self.request(method="GET", body=b"not-empty")
        self.assertEqual((s, d["error"]), (400, "invalid_request"))

    def test_oversize_body_denied(self):
        s, d, _, _ = self.request(body=b"x" * 8193)
        self.assertEqual((s, d["error"]), (413, "request_too_large"))

    def test_query_string_denied(self):
        s, d, _, _ = self.request(query=b"tenant_id=tenant-b")
        self.assertEqual((s, d["error"]), (400, "invalid_request"))

    def test_encoded_path_denied(self):
        s, d, _, _ = self.request(raw_path=b"/v1/%64rafts")
        self.assertEqual((s, d["error"]), (400, "invalid_request"))

    def test_content_length_mismatch_denied(self):
        s, d, _, _ = self.request(headers=[(b"content-length", b"2")])
        self.assertEqual((s, d["error"]), (400, "invalid_request"))

    def test_explicit_publish_is_forbidden(self):
        s, d, _, _ = self.request(
            method="POST", path="/v1/publish", body=b"{}")
        self.assertEqual((s, d["error"]), (403, "forbidden"))
        self.assertEqual(self.state.list_for_tenant("tenant-a"), [])

    def test_post_tenant_field_denied(self):
        s, d, _, _ = self.request(body=payload(tenant_id="tenant-b"))
        self.assertEqual((s, d["error"]), (422, "invalid_draft"))

    def test_invalid_json_denied(self):
        s, d, _, _ = self.request(body=b"{broken")
        self.assertEqual((s, d["error"]), (422, "invalid_draft"))

    def test_external_upload_does_not_execute(self):
        s, d, _, _ = self.request(body=payload(source_ref="upload:1234567890xyz"))
        self.assertEqual(s, 201)
        self.assertEqual(d["execution"], "DISABLED")

    def test_unsupported_http_methods_denied(self):
        s, d, _, _ = self.request(method="DELETE", body=b"")
        self.assertEqual((s, d["error"]), (403, "forbidden"))


if __name__ == "__main__":
    unittest.main()
