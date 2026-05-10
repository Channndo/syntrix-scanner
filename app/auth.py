"""Argon2 password hashing (passlib) and HS256 JWT mint/decode for email/password auth."""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from jose import jwt
from passlib.context import CryptContext

from app.config import settings

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


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
    """JWT claims: sub, email, iat, exp (7 days). HS256."""
    secret = ensure_jwt_secret()
    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=7)
    payload: Dict[str, Any] = {
        "sub": user_sub,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_access_token(token: str) -> Dict[str, Any]:
    secret = ensure_jwt_secret()
    return jwt.decode(token, secret, algorithms=["HS256"])
