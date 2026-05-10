"""Password + JWT helpers.

**Passwords** — Stored only as **Argon2id** hashes (passlib). Never SHA-256 or plain SHA for passwords.

**JWT access tokens** — Signed with **HS256** (HMAC-SHA256). That is standard for symmetric JWTs: the
secret authenticates the token; it is *not* the same as hashing a password. Upgrading to RS256 would
mean asymmetric keys and key rotation — optional later, not “more secure” HMAC for typical APIs.

Argon2 parameters below favor stronger memory cost than passlib’s legacy defaults; existing hashes
still verify; logins rehash via ``password_needs_rehash`` when params improve.
"""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.config import settings

logger = logging.getLogger(__name__)

# Argon2id (passlib default type). memory_cost is in KiB (65536 ≈ 64 MiB per OWASP-style hardening).
pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__memory_cost=65536,
    argon2__time_cost=3,
    argon2__parallelism=4,
)


def ensure_jwt_secret() -> str:
    """
    Return HS256 signing secret. If SYNTRIX_JWT_SECRET is unset or too short,
    generate an ephemeral secret (dev) and log a warning.
    """
    raw = (getattr(settings, "jwt_secret", None) or "").strip()
    if raw and len(raw) >= 32:
        return raw
    generated = secrets.token_urlsafe(48)
    settings.jwt_secret = generated
    logger.warning(
        "SYNTRIX_JWT_SECRET unset or shorter than 32 characters — generated ephemeral secret for this "
        "process. Set SYNTRIX_JWT_SECRET in production."
    )
    return generated


def normalize_security_answer(plain: str) -> str:
    """Normalize recovery answers: trim, lowercase for stable verification."""
    return normalize_password_input(plain).strip().lower()


def normalize_password_input(plain: str) -> str:
    """
    Remove invisible paste junk (BOM, zero-width) and accidental outer CRLF only.
    Interior spaces are kept so we don't change intentional passwords.
    """
    if plain is None:
        return ""
    s = (
        str(plain)
        .replace("\ufeff", "")
        .replace("\u200b", "")
        .replace("\u200c", "")
        .replace("\u200d", "")
    )
    return s.strip("\r\n")


def hash_password(plain: str) -> str:
    return pwd_context.hash(normalize_password_input(plain))


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(normalize_password_input(plain), hashed)


def password_needs_rehash(hashed: str) -> bool:
    return pwd_context.needs_update(hashed)


def mint_access_token(user_sub: str, email: str) -> str:
    """JWT claims: sub, email, role, iat, exp (7 days). HS256. Passwords only ever stored as Argon2 hashes."""
    secret = ensure_jwt_secret()
    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=7)
    role = "admin" if settings.is_admin_email(email) else "user"
    payload: Dict[str, Any] = {
        "sub": user_sub,
        "email": email,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_access_token(token: str) -> Dict[str, Any]:
    secret = ensure_jwt_secret()
    return jwt.decode(token, secret, algorithms=["HS256"])


def mint_login_challenge_token(user_sub: str, email: str) -> str:
    """Short-lived JWT after password OK; used only to complete security-question step."""
    secret = ensure_jwt_secret()
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=10)
    payload: Dict[str, Any] = {
        "sub": user_sub,
        "email": email.strip().lower(),
        "typ": "login_sq",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_login_challenge_token(token: str) -> Dict[str, Any]:
    secret = ensure_jwt_secret()
    payload = jwt.decode(token, secret, algorithms=["HS256"])
    if payload.get("typ") != "login_sq":
        raise ValueError("invalid challenge token")
    return payload


def mint_password_change_session_token(user_sub: str, email: str) -> str:
    """Short-lived JWT after password verified but rotation / admin force blocks full login."""
    secret = ensure_jwt_secret()
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=15)
    payload: Dict[str, Any] = {
        "sub": user_sub,
        "email": email.strip().lower(),
        "typ": "pw_change",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_password_change_session_token(token: str) -> Dict[str, Any]:
    secret = ensure_jwt_secret()
    payload = jwt.decode(token, secret, algorithms=["HS256"])
    if payload.get("typ") != "pw_change":
        raise ValueError("invalid password-change session token")
    return payload


def mint_device_trust_token(user_sub: str, email: str) -> str:
    """Long-lived JWT for “trusted device” — skip security questions on future password logins."""
    secret = ensure_jwt_secret()
    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=90)
    payload: Dict[str, Any] = {
        "sub": user_sub,
        "email": email.strip().lower(),
        "typ": "device_trust",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def device_trust_token_valid(token: Optional[str], user_sub: str, email: str) -> bool:
    if not token or not str(token).strip():
        return False
    try:
        secret = ensure_jwt_secret()
        payload = jwt.decode(str(token).strip(), secret, algorithms=["HS256"])
        if payload.get("typ") != "device_trust":
            return False
        if payload.get("sub") != user_sub:
            return False
        if (payload.get("email") or "").strip().lower() != email.strip().lower():
            return False
        return True
    except JWTError:
        return False
