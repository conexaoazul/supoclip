"""Persistent local QA draft and nonce ledger. No SupoClip/network side effects."""

import sqlite3
import threading
import time
import uuid


class DuplicateIntentError(ValueError):
    pass


class QueueFullError(ValueError):
    pass


class ClosedIntentError(ValueError):
    pass


# Metadata-only QA lifecycle. Expiry happens synchronously on a later request,
# never via a background job or a SupoClip execution.
DRAFT_TTL_SECONDS = 24 * 60 * 60
CLOSED_RETENTION_SECONDS = 30 * 24 * 60 * 60


class GatewayState:
    """Single-process SQLite ledger for offline QA. Never reuse with production DB."""

    def __init__(self, database=":memory:"):
        self._db = sqlite3.connect(database, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._db.executescript("""
                PRAGMA foreign_keys=ON;
                CREATE TABLE IF NOT EXISTS replay_nonces (
                    key_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    valid_until INTEGER NOT NULL,
                    PRIMARY KEY (key_id, nonce)
                );
                CREATE TABLE IF NOT EXISTS draft_jobs (
                    job_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    idem_key TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    source_ref TEXT NOT NULL,
                    source_duration_seconds INTEGER NOT NULL,
                    clip_length TEXT NOT NULL,
                    consent_ref TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('prepared','closed')),
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    closed_at INTEGER,
                    close_reason TEXT CHECK (
                        close_reason IN ('expired','closed_by_tenant')
                    ),
                    UNIQUE (tenant_id, idem_key)
                );
                CREATE INDEX IF NOT EXISTS draft_tenant_idx
                    ON draft_jobs (tenant_id, state);
            """)

    def close(self):
        with self._lock:
            self._db.close()

    def _advance_lifecycle(self, now):
        """Called inside a transaction; bounded on-demand expiry and cleanup.

        No autonomous clock or thread. Real retention control requires a
        separate infrastructure-approved scheduled job.
        """
        self._db.execute(
            """UPDATE draft_jobs
               SET state='closed', closed_at=expires_at, close_reason='expired'
               WHERE state='prepared' AND expires_at <= ?""",
            (now,),
        )
        self._db.execute(
            """DELETE FROM draft_jobs
               WHERE state='closed' AND closed_at <= ?""",
            (now - CLOSED_RETENTION_SECONDS,),
        )

    def claim_nonce(self, key_id, nonce, valid_until, now):
        """Durable replay rejection for signed QA requests."""
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                self._db.execute("DELETE FROM replay_nonces WHERE valid_until < ?", (now,))
                self._db.execute(
                    "INSERT INTO replay_nonces(key_id, nonce, valid_until) VALUES (?, ?, ?)",
                    (key_id, nonce, valid_until),
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def prepare(self, *, tenant_id, idem_key, payload_hash, source_ref,
                source_duration_seconds, clip_length, consent_ref, now=None,
                max_pending=3):
        """Atomically deduplicate or reserve an isolated metadata-only draft."""
        now = int(time.time() if now is None else now)
        if not isinstance(max_pending, int) or max_pending < 1:
            raise ValueError("invalid_queue_limit")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                existing = self._db.execute(
                    "SELECT * FROM draft_jobs WHERE tenant_id=? AND idem_key=?",
                    (tenant_id, idem_key),
                ).fetchone()
                if existing:
                    if existing["state"] != "prepared":
                        raise ClosedIntentError("idempotency_closed")
                    if existing["payload_hash"] != payload_hash:
                        raise DuplicateIntentError("idempotency_conflict")
                    self._db.execute("COMMIT")
                    return dict(existing), False
                count = self._db.execute(
                    "SELECT COUNT(*) FROM draft_jobs WHERE tenant_id=? AND state='prepared'",
                    (tenant_id,),
                ).fetchone()[0]
                if count >= max_pending:
                    raise QueueFullError("tenant_queue_limit")
                job_id = uuid.uuid4().hex
                self._db.execute(
                    """INSERT INTO draft_jobs
                       (job_id,tenant_id,idem_key,payload_hash,source_ref,
                        source_duration_seconds,clip_length,consent_ref,state,
                        created_at,expires_at)
                       VALUES (?,?,?,?,?,?,?,?,'prepared',?,?)""",
                    (job_id, tenant_id, idem_key, payload_hash, source_ref,
                     source_duration_seconds, clip_length, consent_ref,
                     now, now + DRAFT_TTL_SECONDS),
                )
                draft = dict(self._db.execute(
                    "SELECT * FROM draft_jobs WHERE job_id=?", (job_id,),
                ).fetchone())
                self._db.execute("COMMIT")
                return draft, True
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def _read_after_lifecycle(self, now, sql, params, many=False):
        """Complete lazy expiry in one transaction, including read paths."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._advance_lifecycle(now)
                rows = self._db.execute(sql, params)
                result = rows.fetchall() if many else rows.fetchone()
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
            if many:
                return [dict(row) for row in result]
            return dict(result) if result is not None else None

    def get_for_tenant(self, tenant_id, job_id, *, now=None):
        now = int(time.time() if now is None else now)
        return self._read_after_lifecycle(
            now,
            "SELECT * FROM draft_jobs WHERE tenant_id=? AND job_id=?",
            (tenant_id, job_id),
        )

    def list_for_tenant(self, tenant_id, *, now=None):
        now = int(time.time() if now is None else now)
        return self._read_after_lifecycle(
            now,
            """SELECT * FROM draft_jobs WHERE tenant_id=?
               ORDER BY created_at DESC,job_id DESC""",
            (tenant_id,),
            many=True,
        )

    def close_for_tenant(self, tenant_id, job_id, *, now=None):
        """Manual metadata closure (never cancellation of an engine task).

        Returns None for absent/foreign jobs; always requires tenant binding.
        """
        now = int(time.time() if now is None else now)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._advance_lifecycle(now)
                row = self._db.execute(
                    "SELECT * FROM draft_jobs WHERE tenant_id=? AND job_id=?",
                    (tenant_id, job_id),
                ).fetchone()
                if row is not None and row["state"] == "prepared":
                    self._db.execute(
                        """UPDATE draft_jobs SET state='closed', closed_at=?,
                           close_reason='closed_by_tenant'
                           WHERE tenant_id=? AND job_id=? AND state='prepared'""",
                        (now, tenant_id, job_id),
                    )
                    row = self._db.execute(
                        "SELECT * FROM draft_jobs WHERE tenant_id=? AND job_id=?",
                        (tenant_id, job_id),
                    ).fetchone()
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
            return dict(row) if row is not None else None
