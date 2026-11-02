"""Offline QA-only, signer-verified rights ledger with durable revocations.

NOT a legal consent system, NOT a production KMS, NOT a remote API.
Separate review keys MUST be injected from a trusted non-client source.
No review signing key may be shared with the HMAC gateway keyring.
Signer identity by itself does not prove that client media is licensed.
"""

from dataclasses import asdict
import hashlib
import hmac
import json
import re
import sqlite3
import threading
import time

from .media_evidence import (
    RightsApproval, APPROVER_RE, HASH_RE, REF_RE, TENANT_RE, UPLOAD_ID_RE,
)

REVIEW_WINDOW_SECONDS = 300
MAX_APPROVAL_SECONDS = 30 * 86400
SIGNATURE_RE = re.compile(r"^[0-9a-f]{64}$")


class RightsLedgerDenied(ValueError):
    """Safe reason; never includes credentials or database path."""


class RightsLedgerUnavailable(RuntimeError):
    """Persistent ledger operation failed; callers must fail closed."""


def _canonical_event(action, payload):
    """Stable, domain-separated bytes for an independent reviewer signature."""
    if action not in ("approve", "revoke") or not isinstance(payload, dict):
        raise RightsLedgerDenied("invalid_event")
    return (
        "blue-video-qa-review-v1\n" + action + "\n"
        + json.dumps(payload, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False)
    ).encode("utf-8")


def _valid_approval(record, reviewer, now):
    if not isinstance(record, RightsApproval):
        return False
    if (not isinstance(record.tenant_id, str)
            or TENANT_RE.fullmatch(record.tenant_id) is None
            or not isinstance(record.source_ref, str)
            or UPLOAD_ID_RE.fullmatch(record.source_ref) is None
            or not isinstance(record.source_sha256, str)
            or HASH_RE.fullmatch(record.source_sha256) is None
            or not isinstance(record.rights_ref, str)
            or REF_RE.fullmatch(record.rights_ref) is None
            or not isinstance(record.approved_by, str)
            or APPROVER_RE.fullmatch(record.approved_by) is None
            or record.approved_by != reviewer
            or type(record.approved_at) is not int
            or type(record.valid_until) is not int
            or record.processing_allowed is not True):
        return False
    return (
        abs(record.approved_at - now) <= REVIEW_WINDOW_SECONDS
        and record.valid_until > now
        and record.valid_until - record.approved_at <= MAX_APPROVAL_SECONDS
    )


class QASignedRightsLedger:
    """Single-process QA SQLite ledger. Isolate DB file and reviewer keys.

    Reviews are externally signed before reaching this object; this module
    *verifies* them, never signs an approval or infers consent from an upload.
    Never reuse this SQLite ledger for a production multi-node deployment.
    """

    def __init__(self, database, *, review_keys, clock=None):
        if not isinstance(database, str) or not database:
            raise RightsLedgerDenied("invalid_database")
        if not isinstance(review_keys, dict) or not review_keys:
            raise RightsLedgerDenied("review_keys_required")
        self._keys = {}
        for reviewer, key in review_keys.items():
            if (not isinstance(reviewer, str)
                    or APPROVER_RE.fullmatch(reviewer) is None
                    or not isinstance(key, bytes) or len(key) < 32):
                raise RightsLedgerDenied("invalid_reviewer_key")
            self._keys[reviewer] = key
        self._clock = clock or time.time
        self._lock = threading.RLock()
        try:
            self._db = sqlite3.connect(
                database, check_same_thread=False, isolation_level=None,
                timeout=2,
            )
            self._db.row_factory = sqlite3.Row
            self._db.executescript("""
                PRAGMA busy_timeout=2000;
                CREATE TABLE IF NOT EXISTS signed_qa_rights (
                    tenant_id TEXT NOT NULL,
                    source_ref TEXT NOT NULL,
                    source_sha256 TEXT NOT NULL,
                    rights_ref TEXT NOT NULL,
                    approved_by TEXT NOT NULL,
                    approved_at INTEGER NOT NULL,
                    valid_until INTEGER NOT NULL,
                    processing_allowed INTEGER NOT NULL CHECK (processing_allowed=1),
                    approval_signature TEXT NOT NULL,
                    revoked_at INTEGER,
                    revoked_by TEXT,
                    revocation_signature TEXT,
                    PRIMARY KEY (tenant_id, source_ref)
                );
            """)
        except sqlite3.Error as exc:
            raise RightsLedgerUnavailable("qa_ledger_unavailable") from exc

    def close(self):
        with self._lock:
            self._db.close()

    def _verify(self, action, payload, reviewer, signature):
        if (reviewer not in self._keys
                or not isinstance(signature, str)
                or SIGNATURE_RE.fullmatch(signature) is None):
            raise RightsLedgerDenied("review_signature_invalid")
        expected = hmac.new(
            self._keys[reviewer], _canonical_event(action, payload),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise RightsLedgerDenied("review_signature_invalid")

    def approve(self, record, *, signature):
        reviewer = record.approved_by if isinstance(record, RightsApproval) else None
        now = int(self._clock())
        if not _valid_approval(record, reviewer, now):
            raise RightsLedgerDenied("review_record_invalid_or_expired")
        payload = asdict(record)
        self._verify("approve", payload, reviewer, signature)
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                self._db.execute(
                    """INSERT INTO signed_qa_rights
                       (tenant_id,source_ref,source_sha256,rights_ref,
                        approved_by,approved_at,valid_until,processing_allowed,
                        approval_signature)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (
                        record.tenant_id, record.source_ref,
                        record.source_sha256, record.rights_ref,
                        record.approved_by, record.approved_at,
                        record.valid_until, 1, signature,
                    ),
                )
                self._db.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                self._db.execute("ROLLBACK")
                raise RightsLedgerDenied("review_already_registered") from exc
            except sqlite3.Error as exc:
                self._db.execute("ROLLBACK")
                raise RightsLedgerUnavailable("qa_ledger_unavailable") from exc

    def revoke(self, *, tenant_id, source_ref, rights_ref, reviewer,
               revoked_at, signature):
        now = int(self._clock())
        if (not isinstance(tenant_id, str)
                or TENANT_RE.fullmatch(tenant_id) is None
                or not isinstance(source_ref, str)
                or UPLOAD_ID_RE.fullmatch(source_ref) is None
                or not isinstance(rights_ref, str)
                or REF_RE.fullmatch(rights_ref) is None
                or type(revoked_at) is not int
                or abs(revoked_at - now) > REVIEW_WINDOW_SECONDS):
            raise RightsLedgerDenied("invalid_revocation")
        payload = {
            "tenant_id": tenant_id, "source_ref": source_ref,
            "rights_ref": rights_ref, "revoked_by": reviewer,
            "revoked_at": revoked_at,
        }
        self._verify("revoke", payload, reviewer, signature)
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                cursor = self._db.execute(
                    """UPDATE signed_qa_rights SET revoked_at=?,
                              revoked_by=?, revocation_signature=?
                       WHERE tenant_id=? AND source_ref=? AND rights_ref=?
                             AND revoked_at IS NULL""",
                    (
                        revoked_at, reviewer, signature,
                        tenant_id, source_ref, rights_ref,
                    ),
                )
                if cursor.rowcount != 1:
                    raise RightsLedgerDenied("review_missing_or_revoked")
                self._db.execute("COMMIT")
            except Exception as exc:
                self._db.execute("ROLLBACK")
                if isinstance(exc, RightsLedgerDenied):
                    raise
                raise RightsLedgerUnavailable("qa_ledger_unavailable") from exc

    def lookup(self, tenant_id, source_ref):
        """Trusted callback for TrustedUploadAttestor; lookup is fail-closed."""
        if (not isinstance(tenant_id, str)
                or TENANT_RE.fullmatch(tenant_id) is None
                or not isinstance(source_ref, str)
                or UPLOAD_ID_RE.fullmatch(source_ref) is None):
            raise RightsLedgerDenied("invalid_lookup")
        with self._lock:
            try:
                row = self._db.execute(
                    """SELECT * FROM signed_qa_rights
                       WHERE tenant_id=? AND source_ref=?""",
                    (tenant_id, source_ref),
                ).fetchone()
            except sqlite3.Error as exc:
                raise RightsLedgerUnavailable("qa_ledger_unavailable") from exc
        if row is None or row["revoked_at"] is not None:
            return None
        record = RightsApproval(
            tenant_id=row["tenant_id"], source_ref=row["source_ref"],
            source_sha256=row["source_sha256"], rights_ref=row["rights_ref"],
            approved_by=row["approved_by"], approved_at=row["approved_at"],
            valid_until=row["valid_until"], processing_allowed=(
                row["processing_allowed"] == 1),
        )
        try:
            self._verify(
                "approve", asdict(record), record.approved_by,
                row["approval_signature"],
            )
        except RightsLedgerDenied as exc:
            raise RightsLedgerUnavailable("qa_ledger_signature_invalid") from exc
        if not _valid_approval_at_lookup(record, int(self._clock())):
            return None
        return record


def _valid_approval_at_lookup(record, now):
    return (
        isinstance(record, RightsApproval)
        and type(record.approved_at) is int
        and type(record.valid_until) is int
        and record.approved_at <= now <= record.valid_until
        and record.processing_allowed is True
    )
