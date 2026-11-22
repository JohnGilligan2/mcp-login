"""Durable state, in SQLite on the service's volume.

Everything that is a credential (authorization codes, refresh tokens) is stored
only as a SHA-256 hash, so a copy of the database cannot be replayed. Pending
sign-ins and upstream flows are short-lived and swept.

Calls are tiny local writes, so they run inline on the event loop behind one
lock rather than in a thread pool; there is no network I/O in here.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS pending (
    id TEXT PRIMARY KEY, client_id TEXT, redirect_uri TEXT, state TEXT,
    code_challenge TEXT, code_challenge_method TEXT, scope TEXT, nonce TEXT,
    resource TEXT, created REAL);
CREATE TABLE IF NOT EXISTS flows (
    state TEXT PRIMARY KEY, pending_id TEXT, idp TEXT, browser TEXT,
    verifier TEXT, nonce TEXT, created REAL);
CREATE TABLE IF NOT EXISTS codes (
    code_hash TEXT PRIMARY KEY, data TEXT, created REAL, used INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS refresh (
    token_hash TEXT PRIMARY KEY, family TEXT, client_id TEXT, data TEXT,
    created REAL, expires REAL, rotated INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS refresh_family ON refresh(family);
"""


def h(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


class Store:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(SCHEMA)
        self._lock = threading.Lock()

    def _x(self, sql: str, args: tuple = ()) -> list[tuple]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    # --- pending authorization requests (Claude/proxy -> us) --------------
    def put_pending(self, **p: Any) -> str:
        pid = new_token(18)
        self._x("INSERT INTO pending VALUES (?,?,?,?,?,?,?,?,?,?)",
                (pid, p["client_id"], p["redirect_uri"], p["state"], p["code_challenge"],
                 p["code_challenge_method"], p["scope"], p["nonce"], p["resource"], time.time()))
        return pid

    def get_pending(self, pid: str, ttl: int) -> dict[str, Any] | None:
        rows = self._x("SELECT client_id, redirect_uri, state, code_challenge, "
                       "code_challenge_method, scope, nonce, resource, created "
                       "FROM pending WHERE id=?", (pid,))
        if not rows or time.time() - rows[0][8] > ttl:
            return None
        k = ("client_id", "redirect_uri", "state", "code_challenge",
             "code_challenge_method", "scope", "nonce", "resource")
        return dict(zip(k, rows[0][:8]))

    def drop_pending(self, pid: str) -> None:
        self._x("DELETE FROM pending WHERE id=?", (pid,))

    # --- upstream flows (us -> Google/Microsoft) ---------------------------
    def put_flow(self, state: str, pending_id: str, idp: str, browser: str,
                 verifier: str, nonce: str) -> None:
        self._x("INSERT INTO flows VALUES (?,?,?,?,?,?,?)",
                (state, pending_id, idp, h(browser), verifier, nonce, time.time()))

    def take_flow(self, state: str, ttl: int) -> dict[str, Any] | None:
        """Single use: the row is deleted as it is read."""
        with self._lock:
            rows = self._db.execute("SELECT pending_id, idp, browser, verifier, nonce, created "
                                    "FROM flows WHERE state=?", (state,)).fetchall()
            self._db.execute("DELETE FROM flows WHERE state=?", (state,))
        if not rows or time.time() - rows[0][5] > ttl:
            return None
        k = ("pending_id", "idp", "browser_hash", "verifier", "nonce")
        return dict(zip(k, rows[0][:5]))

    # --- authorization codes (us -> proxy) ----------------------------------
    def put_code(self, data: dict[str, Any]) -> str:
        code = new_token(32)
        self._x("INSERT INTO codes VALUES (?,?,?,0)", (h(code), json.dumps(data), time.time()))
        return code

    def take_code(self, code: str, ttl: int) -> tuple[str, dict[str, Any] | None]:
        """Returns (status, data). status: ok | unknown | expired | reused.

        A code is marked used rather than deleted, so a second presentation is
        recognisable as replay rather than as an unknown code.
        """
        with self._lock:
            rows = self._db.execute("SELECT data, created, used FROM codes WHERE code_hash=?",
                                    (h(code),)).fetchall()
            if rows and not rows[0][2]:
                self._db.execute("UPDATE codes SET used=1 WHERE code_hash=?", (h(code),))
        if not rows:
            return "unknown", None
        data, created, used = rows[0]
        if used:
            return "reused", json.loads(data)
        if time.time() - created > ttl:
            return "expired", None
        return "ok", json.loads(data)

    # --- refresh tokens -------------------------------------------------------
    def put_refresh(self, client_id: str, data: dict[str, Any], ttl: int,
                    family: str | None = None) -> str:
        tok = new_token(32)
        now = time.time()
        self._x("INSERT INTO refresh VALUES (?,?,?,?,?,?,0)",
                (h(tok), family or new_token(12), client_id, json.dumps(data), now, now + ttl))
        return tok

    def rotate_refresh(self, token: str, client_id: str) -> tuple[str, dict[str, Any] | None, str | None]:
        """Returns (status, data, family). status: ok | unknown | expired | reused | wrong_client.

        On `reused` the whole family is revoked: a refresh token presented after
        it was already rotated means two parties hold it, and one of them is
        not the customer.
        """
        with self._lock:
            rows = self._db.execute("SELECT family, client_id, data, expires, rotated FROM refresh "
                                    "WHERE token_hash=?", (h(token),)).fetchall()
            if not rows:
                return "unknown", None, None
            family, cid, data, expires, rotated = rows[0]
            if rotated:
                self._db.execute("DELETE FROM refresh WHERE family=?", (family,))
                return "reused", None, family
            if cid != client_id:
                return "wrong_client", None, family
            if time.time() > expires:
                return "expired", None, family
            self._db.execute("UPDATE refresh SET rotated=1 WHERE token_hash=?", (h(token),))
        return "ok", json.loads(data), family

    def revoke_family(self, family: str) -> None:
        self._x("DELETE FROM refresh WHERE family=?", (family,))

    def sweep(self, pending_ttl: int, code_ttl: int) -> None:
        now = time.time()
        self._x("DELETE FROM pending WHERE created < ?", (now - pending_ttl,))
        self._x("DELETE FROM flows WHERE created < ?", (now - pending_ttl,))
        # Used/expired codes are kept an hour so replay stays recognisable.
        self._x("DELETE FROM codes WHERE created < ?", (now - max(code_ttl, 3600),))
        # Rotated tokens are kept until the family expires, for reuse detection.
        self._x("DELETE FROM refresh WHERE expires < ?", (now,))
