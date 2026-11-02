"""Internal ASGI HTTP adapter for OFFLINE QA draft metadata only.

This module defines a factory. It does NOT create a global ASGI application,
open sockets, read environment variables, connect to SupoClip, or launch jobs.
It must NOT be exposed to the Internet or production. TLS/private ingress and
request timeouts are external deployment responsibilities subject to QA GO.
"""

import json
import re

from .core import AuthFailure, BlueVideoGateway, PolicyFailure


class BadEnvelope(ValueError):
    """Safe request-level error code."""


REQUIRED_AUTH = (
    "x-blue-key-id", "x-blue-timestamp", "x-blue-nonce", "x-blue-signature",
)
MAX_BODY = 8192
MAX_HEADERS = 32
DRAFT_DETAIL = re.compile(r"^/v1/drafts/([0-9a-f]{32})$")
DRAFT_CLOSE = re.compile(r"^/v1/drafts/([0-9a-f]{32})/close$")


def _headers(scope):
    raw_headers = scope.get("headers", ())
    if not isinstance(raw_headers, (list, tuple)) or len(raw_headers) > MAX_HEADERS:
        raise BadEnvelope("invalid_headers")
    result = {}
    for name, value in raw_headers:
        try:
            key = name.decode("ascii").lower()
            val = value.decode("ascii")
        except (AttributeError, UnicodeError):
            raise BadEnvelope("invalid_headers") from None
        if key in result:
            # A duplicate header is ambiguous between gateway/proxy layers.
            raise BadEnvelope("duplicate_header")
        if not re.fullmatch(r"[a-z0-9-]{1,64}", key):
            raise BadEnvelope("invalid_headers")
        if len(val) > 1024 or "\r" in val or "\n" in val:
            raise BadEnvelope("invalid_headers")
        result[key] = val
    return result


async def _read_body(receive):
    chunks = []
    total = 0
    for _ in range(64):
        message = await receive()
        if message.get("type") != "http.request":
            raise BadEnvelope("invalid_request_stream")
        body = message.get("body", b"")
        if not isinstance(body, bytes):
            raise BadEnvelope("invalid_request_stream")
        total += len(body)
        if total > MAX_BODY:
            raise BadEnvelope("request_too_large")
        chunks.append(body)
        if not message.get("more_body", False):
            return b"".join(chunks)
    raise BadEnvelope("request_too_large")


async def _json(send, status, obj):
    payload = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json; charset=utf-8"),
            (b"cache-control", b"no-store"),
            (b"x-content-type-options", b"nosniff"),
            (b"referrer-policy", b"no-referrer"),
            (b"content-length", str(len(payload)).encode("ascii")),
        ],
    })
    await send({"type": "http.response.body", "body": payload, "more_body": False})


def _principal(headers):
    if not all(header in headers for header in REQUIRED_AUTH):
        raise AuthFailure("missing_auth")
    raw_timestamp = headers["x-blue-timestamp"]
    if not re.fullmatch(r"[0-9]{10,11}", raw_timestamp):
        raise AuthFailure("invalid_timestamp")
    return {
        "key_id": headers["x-blue-key-id"],
        "timestamp": int(raw_timestamp),
        "nonce": headers["x-blue-nonce"],
        "signature": headers["x-blue-signature"],
    }


def create_app(gateway):
    """Inject a configured gateway. No default secret, no global server, no bypass."""
    if not isinstance(gateway, BlueVideoGateway):
        raise TypeError("gateway_required")

    async def app(scope, receive, send):
        if scope.get("type") == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        if scope.get("type") != "http":
            raise RuntimeError("HTTP only; startup/lifespan integration not implemented")
        status = 500
        response = {"error": "internal_error"}
        try:
            # HTTPS must be asserted by a TRUSTED ASGI server/terminating proxy;
            # never promote caller-supplied Forwarded or X-Forwarded-Proto headers.
            if scope.get("scheme") != "https":
                raise BadEnvelope("tls_required")
            path = scope.get("path")
            raw_path = scope.get("raw_path")
            method = scope.get("method")
            if (not isinstance(path, str) or not isinstance(method, str) or
                    scope.get("query_string", b"") != b"" or
                    (raw_path is not None and raw_path != path.encode("ascii", errors="ignore"))):
                raise BadEnvelope("unsupported_request_target")
            if method not in {"GET", "POST"}:
                raise PolicyFailure("operation_not_authorized")
            headers = _headers(scope)
            if "transfer-encoding" in headers:
                raise BadEnvelope("transfer_encoding_not_supported")
            if "content-length" in headers:
                n = headers["content-length"]
                if not n.isdigit() or int(n) > MAX_BODY:
                    raise BadEnvelope("invalid_content_length")
            if path == "/v1/drafts" and method in {"GET", "POST"}:
                principal = _principal(headers)
                if method == "POST":
                    if headers.get("content-type") != "application/json":
                        raise BadEnvelope("json_required")
                    body = await _read_body(receive)
                    if "content-length" in headers and len(body) != int(headers["content-length"]):
                        raise BadEnvelope("content_length_mismatch")
                    response = gateway.prepare(**principal, body=body)
                    status = 201 if response["created"] else 200
                else:
                    body = await _read_body(receive)
                    if body:
                        raise BadEnvelope("get_body_forbidden")
                    response = {"drafts": gateway.list_drafts(**principal)}
                    status = 200
            elif method == "GET" and (match := DRAFT_DETAIL.fullmatch(path)):
                body = await _read_body(receive)
                if body:
                    raise BadEnvelope("get_body_forbidden")
                principal = _principal(headers)
                result = gateway.get_draft(**principal, job_id=match.group(1))
                if result is None:
                    status, response = 404, {"error": "not_found"}
                else:
                    status, response = 200, result
            elif method == "POST" and (match := DRAFT_CLOSE.fullmatch(path)):
                # Closing a metadata draft never calls or cancels SupoClip.
                # No HTTP request body is permitted; the signature binds to
                # the exact tenant-owned close path.
                body = await _read_body(receive)
                if body:
                    raise BadEnvelope("close_body_forbidden")
                principal = _principal(headers)
                result = gateway.close_draft(**principal, job_id=match.group(1))
                if result is None:
                    status, response = 404, {"error": "not_found"}
                else:
                    status, response = 200, result
            else:
                # Never silently expose SupoClip publishing, export or social routes.
                raise PolicyFailure("operation_not_authorized")
        except AuthFailure:
            status, response = 401, {"error": "unauthorized"}
        except PolicyFailure as exc:
            reason = str(exc)
            if reason in {"idempotency_conflict", "idempotency_closed"}:
                status, response = 409, {"error": reason}
            elif reason == "tenant_queue_limit":
                status, response = 429, {"error": "queue_limit"}
            elif reason == "operation_not_authorized":
                status, response = 403, {"error": "forbidden"}
            else:
                status, response = 422, {"error": "invalid_draft"}
        except BadEnvelope as exc:
            if str(exc) == "request_too_large":
                status, response = 413, {"error": "request_too_large"}
            elif str(exc) == "tls_required":
                status, response = 426, {"error": "tls_required"}
            else:
                status, response = 400, {"error": "invalid_request"}
        except Exception:
            # Avoid reflecting SQL, secret, media URL or internal exception text.
            status, response = 503, {"error": "unavailable"}
        await _json(send, status, response)

    return app
