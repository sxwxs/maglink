"""Persistence for pending login requests and rate-limit counters."""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import asdict, dataclass
from typing import Optional, Protocol


@dataclass
class StoredRequest:
    request_id: str
    email: str
    user_code: str
    verify_token: str
    status: str
    created_at: float
    expires_at: float


class TokenStore(Protocol):
    def put(self, req: StoredRequest) -> None: ...
    def get(self, request_id: str) -> Optional[StoredRequest]: ...
    def get_by_token(self, verify_token: str) -> Optional[StoredRequest]: ...
    def set_status(self, request_id: str, expect: str, new: str) -> bool: ...
    def delete(self, request_id: str) -> None: ...
    def purge_expired(self, now: float) -> None: ...
    def incr_rate(self, key: str, window_start: float, ttl: float) -> int: ...


class MemoryStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_id: dict[str, StoredRequest] = {}
        self._token_idx: dict[str, str] = {}
        self._rates: dict[str, tuple[float, int]] = {}  # key -> (expires_at, count)

    def put(self, req: StoredRequest) -> None:
        with self._lock:
            self._by_id[req.request_id] = req
            self._token_idx[req.verify_token] = req.request_id

    def get(self, request_id: str) -> Optional[StoredRequest]:
        with self._lock:
            req = self._by_id.get(request_id)
            return StoredRequest(**asdict(req)) if req else None

    def get_by_token(self, verify_token: str) -> Optional[StoredRequest]:
        with self._lock:
            request_id = self._token_idx.get(verify_token)
            req = self._by_id.get(request_id) if request_id else None
            return StoredRequest(**asdict(req)) if req else None

    def set_status(self, request_id: str, expect: str, new: str) -> bool:
        with self._lock:
            req = self._by_id.get(request_id)
            if req is None or req.status != expect:
                return False
            req.status = new
            return True

    def delete(self, request_id: str) -> None:
        with self._lock:
            req = self._by_id.pop(request_id, None)
            if req:
                self._token_idx.pop(req.verify_token, None)

    def purge_expired(self, now: float) -> None:
        with self._lock:
            dead = [rid for rid, req in self._by_id.items() if req.expires_at < now]
            for request_id in dead:
                req = self._by_id.pop(request_id)
                self._token_idx.pop(req.verify_token, None)
            self._rates = {
                key: value for key, value in self._rates.items() if value[0] > now
            }

    def incr_rate(self, key: str, now: float, ttl: float) -> int:
        with self._lock:
            expires_at, count = self._rates.get(key, (now + ttl, 0))
            if expires_at <= now:
                expires_at, count = now + ttl, 0
            count += 1
            self._rates[key] = (expires_at, count)
            return count


_SCHEMA = """
CREATE TABLE IF NOT EXISTS maglink_requests (
    request_id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    user_code TEXT NOT NULL,
    verify_token TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_maglink_requests_token
ON maglink_requests(verify_token);
CREATE TABLE IF NOT EXISTS maglink_rates (
    key TEXT PRIMARY KEY,
    window_start REAL NOT NULL,
    expires_at REAL NOT NULL,
    count INTEGER NOT NULL
);
"""


class SqliteStore:
    """SQLite-backed store suitable for restarts and multiple web processes."""

    def __init__(self, path: str = "maglink.db") -> None:
        self.path = path
        self._local = threading.local()
        conn = self._connection()
        conn.executescript(_SCHEMA)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(maglink_rates)")}
        if "expires_at" not in columns:
            conn.execute(
                "ALTER TABLE maglink_rates ADD COLUMN expires_at REAL NOT NULL DEFAULT 0"
            )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_maglink_rates_expiry ON maglink_rates(expires_at)"
        )
        conn.commit()

    def _connection(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=30000")
            self._local.conn = conn
        return conn

    @staticmethod
    def _request(row: sqlite3.Row) -> StoredRequest:
        return StoredRequest(**dict(row))

    def put(self, req: StoredRequest) -> None:
        self._connection().execute(
            "INSERT OR REPLACE INTO maglink_requests "
            "(request_id,email,user_code,verify_token,status,created_at,expires_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (
                req.request_id,
                req.email,
                req.user_code,
                req.verify_token,
                req.status,
                req.created_at,
                req.expires_at,
            ),
        )

    def get(self, request_id: str) -> Optional[StoredRequest]:
        row = self._connection().execute(
            "SELECT * FROM maglink_requests WHERE request_id=?", (request_id,)
        ).fetchone()
        return self._request(row) if row else None

    def get_by_token(self, verify_token: str) -> Optional[StoredRequest]:
        row = self._connection().execute(
            "SELECT * FROM maglink_requests WHERE verify_token=?", (verify_token,)
        ).fetchone()
        return self._request(row) if row else None

    def set_status(self, request_id: str, expect: str, new: str) -> bool:
        cursor = self._connection().execute(
            "UPDATE maglink_requests SET status=? WHERE request_id=? AND status=?",
            (new, request_id, expect),
        )
        return cursor.rowcount == 1

    def delete(self, request_id: str) -> None:
        self._connection().execute(
            "DELETE FROM maglink_requests WHERE request_id=?", (request_id,)
        )

    def purge_expired(self, now: float) -> None:
        self._connection().execute(
            "DELETE FROM maglink_requests WHERE expires_at < ?", (now,)
        )

    def incr_rate(self, key: str, now: float, ttl: float) -> int:
        conn = self._connection()
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute("DELETE FROM maglink_rates WHERE expires_at <= ?", (now,))
            row = conn.execute(
                "SELECT window_start,expires_at,count FROM maglink_rates WHERE key=?",
                (key,),
            ).fetchone()
            if row is None:
                start, expires_at, count = now, now + ttl, 1
            else:
                start = float(row["window_start"])
                expires_at = float(row["expires_at"])
                count = int(row["count"]) + 1
            conn.execute(
                "INSERT INTO maglink_rates(key,window_start,expires_at,count) VALUES(?,?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET window_start=excluded.window_start,"
                "expires_at=excluded.expires_at,count=excluded.count",
                (key, start, expires_at, count),
            )
            conn.execute("COMMIT")
            return count
        except Exception:
            conn.execute("ROLLBACK")
            raise
