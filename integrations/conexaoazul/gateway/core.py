"""Fail-closed, network-free BlueOps video gateway core.

Not an HTTP endpoint, not a SupoClip client, not a production authorization
system. Caller must provide raw request bytes and trusted server-side keyring.
The HMAC principal/tenant binding is never accepted from JSON input.
"""

import dataclasses
import hashlib
import hmac
import json
import re
import time
from urllib.parse import parse_qsl, urlsplit

from .evidence_binding import TrustedUploadAttestor
from .media_evidence import EvidenceDenied
from .state import (ClosedIntentError, DuplicateIntentError, EvidenceBindingError,
                    GatewayState, QueueFullError)


class AuthFailure(ValueError):
    """Authenticated request is missing, invalid, expired or replayed."""


class PolicyFailure(ValueError):
    """Safe client-facing policy error without secret or SQL detail."""


@dataclasses.dataclass(frozen=True)
class VerificationKey:
    tenant_id: str
    secret: bytes
    enabled: bool = True

    def __post_init__(self):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{1,79}", self.tenant_id):
            raise ValueError("invalid_tenant_key_mapping")
        if not isinstance(self.secret, bytes) or len(self.secret) < 32:
            raise ValueError("weak_hmac_key")


YT_ID = re.compile(r"^[A-Za-z0-9_-]{11}$")
UPLOAD = re.compile(r"^upload:[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")
OP_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")
RIGHTS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{4,159}$")
NONCE = re.compile(r"^[A-Za-z0-9_-]{16,96}$")
KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,79}$")
CANONICAL_FIELDS = frozenset({
    "source_ref", "rights_confirmed", "consent_ref", "clip_length",
    "idempotency_key", "source_duration_seconds"
})
CLIP_LENGTHS = frozenset({"auto", "short", "medium", "long"})


def _unique_pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise PolicyFailure("duplicate_json_key")
        obj[key] = value
    return obj


def _decode_request(raw):
    if not isinstance(raw, bytes) or not 2 <= len(raw) <= 8192:
        raise PolicyFailure("invalid_payload_size")
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise PolicyFailure("invalid_json") from exc
    if not isinstance(obj, dict) or set(obj) != CANONICAL_FIELDS:
        raise PolicyFailure("invalid_request_fields")
    if obj["rights_confirmed"] is not True:
        raise PolicyFailure("rights_not_verified")
    if not isinstance(obj["consent_ref"], str) or not RIGHTS.fullmatch(obj["consent_ref"]):
        raise PolicyFailure("invalid_rights_reference")
    if not isinstance(obj["clip_length"], str) or obj["clip_length"] not in CLIP_LENGTHS:
        raise PolicyFailure("invalid_clip_length")
    if not isinstance(obj["idempotency_key"], str) or not OP_ID.fullmatch(obj["idempotency_key"]):
        raise PolicyFailure("invalid_idempotency_key")
    duration = obj["source_duration_seconds"]
    if type(duration) is not int or not 1 <= duration <= 1800:
        raise PolicyFailure("invalid_duration")
    obj["source_ref"] = normalize_source(obj["source_ref"])
    return obj


def normalize_source(source):
    """Syntax preflight only. Runtime DNS, redirects and egress still required."""
    if (not isinstance(source, str) or len(source) > 512 or
            source != source.strip() or any(ord(ch) < 33 for ch in source)):
        raise PolicyFailure("invalid_source")
    if UPLOAD.fullmatch(source):
        return source
    try:
        parsed = urlsplit(source)
        port = parsed.port
    except ValueError as exc:
        raise PolicyFailure("invalid_source") from exc
    if (parsed.scheme != "https" or port not in (None, 443) or
            parsed.fragment or not parsed.hostname or parsed.username is not None or
            parsed.password is not None):
        raise PolicyFailure("invalid_source")
    host = parsed.hostname.lower()
    if host in {"www.youtube.com", "youtube.com"} and parsed.path == "/watch":
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if len(pairs) == 1 and pairs[0][0] == "v" and YT_ID.fullmatch(pairs[0][1]):
            return "https://www.youtube.com/watch?v=" + pairs[0][1]
    if host == "youtu.be" and not parsed.query and parsed.path.startswith("/"):
        name = parsed.path[1:]
        if YT_ID.fullmatch(name):
            return "https://www.youtube.com/watch?v=" + name
    raise PolicyFailure("source_not_allowlisted")


def sign_request(secret, *, key_id, timestamp, nonce, method, path, body):
    """Helper for offline QA fixtures, not a user-token generator."""
    parts = [method.upper(), path, key_id, str(timestamp), nonce,
             hashlib.sha256(body).hexdigest()]
    message = "\n".join(parts).encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


class BlueVideoGateway:
    """Private QA domain boundary; only metadata drafts can be prepared.

    No authorization to submit, render, download, export, delete or publish.
    A future HTTP adapter must call authenticate BEFORE choosing operation.
    """

    def __init__(self, *, keys, state, clock=None, upload_attestor=None):
        self._keys = dict(keys)
        if not isinstance(state, GatewayState):
            raise TypeError("invalid_state")
        if upload_attestor is not None and not isinstance(
                upload_attestor, TrustedUploadAttestor):
            raise TypeError("invalid_upload_attestor")
        self._state = state
        self._clock = clock or time.time
        self._upload_attestor = upload_attestor

    def authenticate(self, *, key_id, signature, timestamp, nonce, method,
                     path, body):
        if (not isinstance(key_id, str) or not KEY_ID.fullmatch(key_id) or
                not isinstance(nonce, str) or not NONCE.fullmatch(nonce) or
                not isinstance(signature, str) or not re.fullmatch(r"[a-f0-9]{64}", signature) or
                type(timestamp) is not int or not isinstance(body, bytes)):
            raise AuthFailure("invalid_auth_envelope")
        entry = self._keys.get(key_id)
        if not isinstance(entry, VerificationKey) or entry.enabled is not True:
            raise AuthFailure("unknown_or_revoked_key")
        now = int(self._clock())
        if abs(now - timestamp) > 300:
            raise AuthFailure("signature_expired")
        expected = sign_request(entry.secret, key_id=key_id, timestamp=timestamp,
                                nonce=nonce, method=method, path=path, body=body)
        if not hmac.compare_digest(signature, expected):
            raise AuthFailure("invalid_signature")
        try:
            self._state.claim_nonce(key_id, nonce, timestamp + 300, now)
        except Exception as exc:
            # Includes database failure and uniqueness violation: fail closed.
            raise AuthFailure("replayed_or_unavailable_nonce") from exc
        return entry.tenant_id

    def prepare(self, *, key_id, signature, timestamp, nonce, body):
        tenant_id = self.authenticate(
            key_id=key_id, signature=signature, timestamp=timestamp, nonce=nonce,
            method="POST", path="/v1/drafts", body=body,
        )
        payload = _decode_request(body)
        intent = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        digest = hashlib.sha256(intent).hexdigest()
        try:
            draft, created = self._state.prepare(
                tenant_id=tenant_id, idem_key=payload["idempotency_key"],
                payload_hash=digest, source_ref=payload["source_ref"],
                source_duration_seconds=payload["source_duration_seconds"],
                clip_length=payload["clip_length"], consent_ref=payload["consent_ref"],
                now=int(self._clock()), max_pending=3,
            )
        except (ClosedIntentError, DuplicateIntentError, QueueFullError) as exc:
            raise PolicyFailure(str(exc)) from exc
        # No tenant, credentials, rights reference or source URL returned to callers.
        return {"job_id": draft["job_id"], "state": draft["state"],
                "created": created, "execution": "DISABLED"}

    def list_drafts(self, *, key_id, signature, timestamp, nonce):
        body = b""
        tenant_id = self.authenticate(
            key_id=key_id, signature=signature, timestamp=timestamp, nonce=nonce,
            method="GET", path="/v1/drafts", body=body,
        )
        return [{"job_id": d["job_id"], "state": d["state"]}
                for d in self._state.list_for_tenant(tenant_id, now=int(self._clock()))]

    def get_draft(self, *, key_id, signature, timestamp, nonce, job_id):
        """Read metadata of one tenant-owned draft with path-bound signature."""
        if not isinstance(job_id, str) or not re.fullmatch(r"[0-9a-f]{32}", job_id):
            raise PolicyFailure("invalid_job_id")
        tenant_id = self.authenticate(
            key_id=key_id, signature=signature, timestamp=timestamp, nonce=nonce,
            method="GET", path="/v1/drafts/" + job_id, body=b"",
        )
        draft = self._state.get_for_tenant(tenant_id, job_id, now=int(self._clock()))
        if draft is None:
            return None
        return {"job_id": draft["job_id"], "state": draft["state"],
                "execution": "DISABLED"}

    def close_draft(self, *, key_id, signature, timestamp, nonce, job_id):
        """Explicit signed metadata closure, not SupoClip cancel/delete/export.

        On-demand expiry may close the draft first. Missing/foreign IDs yield
        the same response; future orchestrators must not infer access.
        """
        if not isinstance(job_id, str) or not re.fullmatch(r"[0-9a-f]{32}", job_id):
            raise PolicyFailure("invalid_job_id")
        tenant_id = self.authenticate(
            key_id=key_id, signature=signature, timestamp=timestamp, nonce=nonce,
            method="POST", path="/v1/drafts/" + job_id + "/close", body=b"",
        )
        draft = self._state.close_for_tenant(
            tenant_id, job_id, now=int(self._clock()),
        )
        if draft is None:
            return None
        return {"job_id": draft["job_id"], "state": "closed",
                "execution": "DISABLED"}

    def attest_draft_offline(self, *, key_id, signature, timestamp, nonce, job_id):
        """Bind private verified upload evidence to this caller's prepared draft.

        Internal Python API ONLY. No ASGI route, network service, worker, render,
        publish, export or submission. Rights records come from the injected
        trusted server-side lookup, NEVER from caller JSON or headers.
        """
        if not isinstance(job_id, str) or not re.fullmatch(r"[0-9a-f]{32}", job_id):
            raise PolicyFailure("invalid_job_id")
        tenant_id = self.authenticate(
            key_id=key_id, signature=signature, timestamp=timestamp, nonce=nonce,
            method="POST", path="/internal/drafts/" + job_id + "/attest",
            body=b"",
        )
        if self._upload_attestor is None:
            raise PolicyFailure("trusted_media_attestor_not_configured")
        now = int(self._clock())
        try:
            draft = self._state.get_for_tenant(tenant_id, job_id, now=now)
            if not draft or draft["state"] != "prepared":
                raise PolicyFailure("draft_missing_closed_or_foreign")
            evidence = self._upload_attestor.attest(
                tenant_id=tenant_id, draft=draft, now=now)
            created = self._state.bind_verified_upload(
                tenant_id=tenant_id, job_id=job_id, evidence=evidence, now=now)
        except (EvidenceDenied, EvidenceBindingError) as exc:
            raise PolicyFailure(str(exc)) from exc
        return {"job_id": job_id, "evidence_status": "verified",
                "created": created, "execution": "DISABLED"}

    @staticmethod
    def deny_unsafe_action(action):
        raise PolicyFailure("operation_not_authorized")

    @staticmethod
    def prepare_upstream_task(draft, *, network_enabled=False):
        """Describe, never perform, the canonical SupoClip POST /tasks/ call.

        Uploaded media first needs a separately approved upload-ticket workflow.
        The pilot core deliberately DOES NOT implement an HTTP client.
        """
        if network_enabled:
            raise PolicyFailure("network_execution_not_implemented")
        if not isinstance(draft, dict) or draft.get("state") != "prepared":
            raise PolicyFailure("invalid_draft")
        src = draft.get("source_ref")
        if not isinstance(src, str) or not src.startswith("https://www.youtube.com/watch?v="):
            raise PolicyFailure("upload_bridge_not_implemented")
        return {"method": "POST", "path": "/tasks/",
                "json": {"source": {"url": src}, "clip_length": draft["clip_length"]},
                "execution": "DISABLED"}
