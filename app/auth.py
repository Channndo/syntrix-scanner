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
from typing import Any, Dict

from jose import jwt
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


def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


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
