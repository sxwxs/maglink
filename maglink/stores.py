"""Persistence for pending login requests + rate-limit counters.

A login request is keyed by ``request_id`` (the value bound to the browser
session). The verify token and the user code are looked up via secondary
indexes so the email link (token) and the polling device (request_id) can both
resolve the same record.

``MemoryStore`` is for tests/single-process. ``SqliteStore`` is the default for
real deployments — it survives restarts and is shared across workers. Both
guard mutations with a lock / transaction so single-use consumption is atomic.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass, asdict
from typing import Optional, Protocol


@dataclass
class StoredRequest:
    request_id: str
    email: str
    user_code: str
    verify_token: str
    status: str  # "pending" | "approved" | "consumed"
    created_at: float
    expires_at: float


class TokenStore(Protocol):
    """Pluggable backing store. Implement this for Redis/other backends."""

    def put(self, req: StoredRequest) -> None: ...
    def get(self, request_id: str) -> Optional[StoredRequest]: ...
    def get_by_token(self, verify_token: str) -> Optional[StoredRequest]: ...
    def set_status(self, request_id: str, expect: str, new: str) -> bool:
        """Atomic compare-and-set. Returns False if current status != expect."""
        ...

    def delete(self, request_id: str) -> None: ...
    def purge_expired(self, now: float) -> None: ...

    # rate limiting
    def incr_rate(self, key: str, window_start: float, ttl: float) -> int:
        """Increment and return the counter for ``key`` in its current window."""
        ...


def _now() -> float:
    return time.time()


class MemoryStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_id: dict[str, StoredRequest] = {}
        self._token_idx: dict[str, str] = {}  # verify_token -> request_id
        self._rates: dict[str, tuple[float, int]] = {}  # key -> (window_start, count)

    def put(self, req: StoredRequest) -> None:
        with self._lock:
            self._by_id[req.request_id] = req
            self._token_idx[req.verify_token] = req.request_id

    def get(self, request_id: str) -> Optional[StoredRequest]:
        with self._lock:
            r = self._by_id.get(request_id)
            return StoredRequest(**asdict(r)) if r else None

    def get_by_token(self, verify_token: str) -> Optional[StoredRequest]:
        with self._lock:
            rid = self._token_idx.get(verify_token)
            r = self._by_id.get(rid) if rid else None
            return StoredRequest(**asdict(r)) if r else None

    def set_status(self, request_id: str, expect: str, new: str) -> bool:
        with self._lock:
            r = self._by_id.get(request_id)
            if r is None or r.status != expect:
                return False
            r.status = new
            return True

    def delete(self, request_id: str) -> None:
        with self._lock:
            r = self._by_id.pop(request_id, None)
            if r:
                self._token_idx.pop(r.verify_token, None)

    def purge_expired(self, now: float) -> None:
        with self._lock:
            dead = [rid for rid, r in self._by_id.items() if r.expires_at < now]
            for rid in dead:
                r = self._by_id.pop(rid, None)
                if r:
                    self._token_idx.pop(r.verify_token, None)

    def incr_rate(self, key: str, window_start: float, ttl: float) -> int:
        with self._lock:
            ws, count = self._rates.get(key, (window_start, 0))
            if window_start - ws >= ttl:
                ws, count = window_start, 0
            count += 1
            self._rates[key] = (ws, count)
            return count


_SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    request_id   TEXT PRIMARY KEY,
    email        TEXT NOT NULL,
    user_code    TEXT NOT NULL,
    verify_token TEXT NOT NULL UNIQUE,
    status       TEXT NOT NULL,
    created_at   REAL NOT NULL,
    expires_at   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_requests_token ON requests(verify_token);
CREATE TABLE IF NOT EXISTS rates (
    key          TEXT PRIMARY KEY,
    window_start REAL NOT NULL,
    count        INTEGER NOT NULL
);
"""


class SqliteStore:
    """File-backed store. Safe across workers via SQLite's transaction locking."""

    def __init__(self, path: str = "maglink.db") -> None:
        self._path = path
        self._lock = threading.Lock()
        # check_same_thread=False + our own lock → usable from a threaded server.
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def _row_to_req(self, row: sqlite3.Row) -> StoredRequest:
        return StoredRequest(
            request_id=row["request_id"],
            email=row["email"],
            user_code=row["user_code"],
            verify_token=row["verify_token"],
            status=row["status"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
        )

    def put(self, req: StoredRequest) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO requests "
                "(request_id, email, user_code, verify_token, status, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (req.request_id, req.email, req.user_code, req.verify_token,
                 req.status, req.created_at, req.expires_at),
            )
            self._conn.commit()

    def get(self, request_id: str) -> Optional[StoredRequest]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM requests WHERE request_id=?", (request_id,)
            ).fetchone()
            return self._row_to_req(row) if row else None

    def get_by_token(self, verify_token: str) -> Optional[StoredRequest]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM requests WHERE verify_token=?", (verify_token,)
            ).fetchone()
            return self._row_to_req(row) if row else None

    def set_status(self, request_id: str, expect: str, new: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE requests SET status=? WHERE request_id=? AND status=?",
                (new, request_id, expect),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def delete(self, request_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM requests WHERE request_id=?", (request_id,))
            self._conn.commit()

    def purge_expired(self, now: float) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM requests WHERE expires_at < ?", (now,))
            self._conn.commit()

    def incr_rate(self, key: str, window_start: float, ttl: float) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT window_start, count FROM rates WHERE key=?", (key,)
            ).fetchone()
            if row is None or window_start - row["window_start"] >= ttl:
                ws, count = window_start, 1
            else:
                ws, count = row["window_start"], row["count"] + 1
            self._conn.execute(
                "INSERT OR REPLACE INTO rates (key, window_start, count) VALUES (?, ?, ?)",
                (key, ws, count),
            )
            self._conn.commit()
            return count
