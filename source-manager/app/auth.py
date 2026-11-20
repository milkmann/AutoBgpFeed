"""Signed cookie authentication, CSRF verification, RBAC, and login rate limiting."""

import base64
from collections import deque
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from fastapi import Depends, HTTPException, Request, status

from .db import get_data_dir, get_db, verify_password

SESSION_COOKIE_NAME = "autobgp_session"
SESSION_TTL_SECONDS = 30 * 24 * 3600  # 30 days
_SECRET_LOCK = threading.Lock()


class LoginRateLimiter:
    """In-memory per-IP login failure rate limiter."""

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300, lockout_seconds: int = 900):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._lock = threading.Lock()
        self._attempts: dict[str, deque[float]] = {}
        self._locked_until: dict[str, float] = {}

    def is_locked(self, ip: str, now: float | None = None) -> tuple[bool, int]:
        ts = time.time() if now is None else now
        with self._lock:
            until = self._locked_until.get(ip, 0.0)
            if until > ts:
                return True, int(until - ts) + 1
            if ip in self._locked_until:
                del self._locked_until[ip]
            return False, 0

    def record_failure(self, ip: str, now: float | None = None) -> tuple[bool, int]:
        ts = time.time() if now is None else now
        with self._lock:
            dq = self._attempts.setdefault(ip, deque())
            cutoff = ts - self.window_seconds
            while dq and dq[0] < cutoff:
                dq.popleft()
            dq.append(ts)
            if len(dq) >= self.max_attempts:
                self._locked_until[ip] = ts + self.lockout_seconds
                dq.clear()
                return True, self.lockout_seconds
            return False, 0

    def clear(self, ip: str) -> None:
        with self._lock:
            self._attempts.pop(ip, None)
            self._locked_until.pop(ip, None)

    def reset(self) -> None:
        with self._lock:
            self._attempts.clear()
            self._locked_until.clear()


login_limiter = LoginRateLimiter()


def get_session_secret() -> str:
    env_secret = os.environ.get("SESSION_SECRET", "").strip()
    if env_secret:
        return env_secret
    data_dir = get_data_dir()
    secret_file = os.path.join(data_dir, ".session_secret")
    with _SECRET_LOCK:
        if os.path.exists(secret_file):
            with open(secret_file, "r", encoding="utf-8") as f:
                val = f.read().strip()
            if val:
                return val
        os.makedirs(data_dir, exist_ok=True)
        val = secrets.token_hex(32)
        tmp_path = secret_file + ".tmp"
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, val.encode("utf-8"))
        finally:
            os.close(fd)
        os.replace(tmp_path, secret_file)
        return val


def get_client_ip(request: Request) -> str:
    trust_proxy = os.environ.get("TRUST_PROXY_HEADERS", "1") == "1"
    if trust_proxy:
        cf_ip = request.headers.get("cf-connecting-ip", "").strip()
        if cf_ip:
            return cf_ip
        xff = request.headers.get("x-forwarded-for", "").strip()
        if xff:
            return xff.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def is_https_request(request: Request) -> bool:
    if request.url.scheme == "https":
        return True
    if os.environ.get("TRUST_PROXY_HEADERS", "1") == "1":
        proto = request.headers.get("x-forwarded-proto", "").lower()
        if proto == "https":
            return True
    return False


def _sign(payload_b64: str, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256).hexdigest()


def create_session_token(user_id: int, username: str, role: str, ttl: int = SESSION_TTL_SECONDS) -> str:
    payload = {
        "uid": int(user_id),
        "u": username,
        "r": role,
        "csrf": secrets.token_hex(16),
        "exp": int(time.time()) + ttl,
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    sig = _sign(payload_b64, get_session_secret())
    return f"{payload_b64}.{sig}"


def decode_session_token(token: str) -> dict | None:
    if not token or "." not in token:
        return None
    try:
        payload_b64, sig = token.split(".", 1)
        expected = _sign(payload_b64, get_session_secret())
        if not secrets.compare_digest(sig, expected):
            return None
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        if int(payload.get("exp", 0)) <= int(time.time()):
            return None
        if not payload.get("uid") or not payload.get("u") or not payload.get("csrf"):
            return None
        return payload
    except Exception:
        return None


def authenticate_user(username: str, password: str) -> dict | None:
    """Verify credentials strictly against the SQLite users table (no .env fallback)."""
    u_clean = username.strip()
    if not u_clean or not password:
        return None
    conn = get_db()
    try:
        row = conn.execute("SELECT id, username, password_hash, role FROM users WHERE username = ?", (u_clean,)).fetchone()
    finally:
        conn.close()
    if row and verify_password(password, row["password_hash"]):
        return {"id": row["id"], "username": row["username"], "role": row["role"]}
    return None


def get_current_user_or_none(request: Request) -> dict | None:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    payload = decode_session_token(token) if token else None
    if not payload:
        return None
    conn = get_db()
    try:
        row = conn.execute("SELECT id, username, role FROM users WHERE id = ?", (payload["uid"],)).fetchone()
    finally:
        conn.close()
    if not row or row["username"] != payload["u"]:
        return None
    return {
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "csrf": payload["csrf"],
    }


class LoginRedirectRequired(Exception):
    """Raised when an unauthenticated browser hits an HTML page."""


def require_user(request: Request) -> dict:
    user = get_current_user_or_none(request)
    if user:
        return user
    if not request.url.path.startswith("/api/"):
        raise LoginRedirectRequired()
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
    )


def require_admin(user: dict = Depends(require_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return user


async def verify_csrf(request: Request, user: dict = Depends(require_user)) -> dict:
    csrf_token = request.headers.get("x-csrf-token", "").strip()
    if not csrf_token:
        content_type = request.headers.get("content-type", "")
        if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
            form = await request.form()
            csrf_token = str(form.get("csrf_token", "")).strip()
    if not csrf_token or not secrets.compare_digest(csrf_token, user["csrf"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing CSRF token",
        )
    return user
