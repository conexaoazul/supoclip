"""Persistent local QA draft and nonce ledger. No SupoClip/network side effects."""

import sqlite3
import threading
import time
import uuid


class DuplicateIntentError(ValueError):
    pass


class QueueFullError(ValueError):
    pass


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
                    UNIQUE (tenant_id, idem_key)
                );
                CREATE INDEX IF NOT EXISTS draft_tenant_idx
                    ON draft_jobs (tenant_id, state);
            """)

    def close(self):
        with self._lock:
            self._db.close()

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
                        source_duration_seconds,clip_length,consent_ref,state,created_at)
                       VALUES (?,?,?,?,?,?,?,?,'prepared',?)""",
                    (job_id, tenant_id, idem_key, payload_hash, source_ref,
                     source_duration_seconds, clip_length, consent_ref, now),
                )
                draft = dict(self._db.execute(
                    "SELECT * FROM draft_jobs WHERE job_id=?", (job_id,),
                ).fetchone())
                self._db.execute("COMMIT")
                return draft, True
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def get_for_tenant(self, tenant_id, job_id):
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM draft_jobs WHERE tenant_id=? AND job_id=?",
                (tenant_id, job_id),
            ).fetchone()
            return dict(row) if row is not None else None

    def list_for_tenant(self, tenant_id):
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM draft_jobs WHERE tenant_id=? ORDER BY created_at DESC,job_id DESC",
                (tenant_id,),
            ).fetchall()
            return [dict(row) for row in rows]
