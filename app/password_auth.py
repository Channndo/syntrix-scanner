"""
Email + password authentication using Argon2id and HS256 JWTs.

NOTE — PAKE / OPAQUE: True password-authenticated key exchange (OPAQUE, SPAKE2,
etc.) avoids ever sending a reusable password-equivalent to the server. This
module uses Argon2id at-rest hashing plus TLS in transit — standard for web apps,
browser-simple, and pairs with future TOTP/WebAuthn second factors.

A dedicated OPAQUE deployment should share wire-compatible client/server libs
(RFC 9807 family); Cloudflare opaque-ts targets an older draft and does not
match common Python opaque-ke / opaque-snake encodings out of the box.
"""

from __future__ import annotations

import re
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import HTTPException, Request, status

from app.config import settings
from app.storage import store

_password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)

_RATE_LOCK = threading.Lock()
_RATE_HITS: Dict[str, List[float]] = {}
_RATE_WINDOW_SEC = 60.0
_RATE_MAX_REQUESTS = 25


def effective_jwt_audience() -> str:
    raw = (settings.jwt_audience or "").strip()
    if raw:
        return raw
    raw = (settings.auth0_audience or "").strip()
    if raw:
        return raw
    return "syntrix-api"


def _issuer() -> str:
    return "syntrix"


def validate_password_policy(password: str) -> None:
    """Minimum 12 chars; must include letters, digits, and at least one symbol/punctuation."""
    if len(password) < 12:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 12 characters.",
        )
    if len(password) > 256:
        raise HTTPException(status_code=400, detail="Password too long.")

    has_letter = any(ch.isalpha() for ch in password)
    has_digit = any(ch.isdigit() for ch in password)
    # Symbols: anything that isn’t a letter, digit, or whitespace (keyboard punctuation, etc.).
    has_special = any(not ch.isalnum() and not ch.isspace() for ch in password)

    if not has_letter:
        raise HTTPException(status_code=400, detail="Password must include at least one letter.")
    if not has_digit:
        raise HTTPException(status_code=400, detail="Password must include at least one number.")
    if not has_special:
        raise HTTPException(
            status_code=400,
            detail="Password must include at least one special character (e.g. ! @ # $ % ^ & *).",
        )


def mint_access_token(user_sub: str, email: Optional[str]) -> str:
    if not settings.jwt_secret or len(settings.jwt_secret) < 32:
        raise RuntimeError("SYNTRIX_JWT_SECRET must be set (min 32 chars) for password auth")
    now = datetime.now(timezone.utc)
    aud = effective_jwt_audience()
    row = store.get_user(user_sub)
    if row is not None:
        auth_ok = int(row.get("authorized", 0)) == 1
    else:
        auth_ok = not settings.require_authorized_account
    payload: Dict[str, Any] = {
        "sub": user_sub,
        "iss": _issuer(),
        "aud": aud,
        "iat": now,
        "exp": now + timedelta(days=7),
        "authorized": auth_ok,
    }
    if email:
        payload["email"] = email
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def decode_password_jwt(token: str) -> Dict[str, Any]:
    aud = effective_jwt_audience()
    return jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=["HS256"],
        audience=aud,
        issuer=_issuer(),
    )


def client_ip(request: Request) -> str:
    ff = (request.headers.get("x-forwarded-for") or "").strip()
    if ff:
        return ff.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def rate_limit_or_429(ip: str) -> None:
    now = time.monotonic()
    with _RATE_LOCK:
        hits = _RATE_HITS.setdefault(ip, [])
        cutoff = now - _RATE_WINDOW_SEC
        while hits and hits[0] < cutoff:
            hits.pop(0)
        if len(hits) >= _RATE_MAX_REQUESTS:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many attempts. Try again shortly.",
            )
        hits.append(now)


def register_email_password(email: str, password: str) -> Dict[str, str]:
    validate_password_policy(password)
    norm_email = email.strip().lower()
    if len(norm_email) < 3 or "@" not in norm_email:
        raise HTTPException(status_code=400, detail="Invalid email.")
    if store.get_password_account_by_email(norm_email):
        raise HTTPException(status_code=409, detail="An account with this email already exists.")

    user_sub = f"local:{uuid.uuid4()}"
    pwd_hash = _password_hasher.hash(password)
    store.ensure_user(user_sub, norm_email)
    try:
        store.register_password_account(user_sub, norm_email, pwd_hash)
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        ) from None
    token = mint_access_token(user_sub, norm_email)
    return {"access_token": token, "token_type": "bearer", "user_sub": user_sub}


def login_email_password(email: str, password: str) -> Dict[str, str]:
    norm_email = email.strip().lower()
    row = store.get_password_account_by_email(norm_email)
    if not row:
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    try:
        _password_hasher.verify(row["password_hash"], password)
    except VerifyMismatchError:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if _password_hasher.check_needs_rehash(row["password_hash"]):
        new_hash = _password_hasher.hash(password)
        with store._lock, store._conn:
            store._conn.execute(
                "UPDATE password_accounts SET password_hash = ? WHERE user_sub = ?",
                (new_hash, row["user_sub"]),
            )

    store.ensure_user(row["user_sub"], norm_email)
    token = mint_access_token(row["user_sub"], norm_email)
    return {"access_token": token, "token_type": "bearer", "user_sub": row["user_sub"]}


def validate_password_auth_config() -> None:
    if not settings.password_auth_enabled:
        return
    if not settings.jwt_secret or len(settings.jwt_secret.strip()) < 32:
        raise RuntimeError(
            "SYNTRIX_PASSWORD_AUTH is enabled but SYNTRIX_JWT_SECRET is missing or shorter than 32 characters."
        )
