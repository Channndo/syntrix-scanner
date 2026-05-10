"""Bearer JWT verification — password (HS256) tokens only."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError

from app.auth import decode_access_token, ensure_jwt_secret
from app.config import settings

logger = logging.getLogger(__name__)

_bearer = HTTPBearer(auto_error=False)


@dataclass
class AuthenticatedUser:
    sub: str
    email: Optional[str]
    raw_claims: Dict[str, Any]


def validate_password_auth_config() -> None:
    if not settings.password_auth_enabled:
        return
    ensure_jwt_secret()


def validate_auth_config() -> None:
    """Startup validation for auth-related settings."""
    validate_password_auth_config()
    if settings.auth_required and not settings.password_auth_enabled:
        logger.warning(
            "SYNTRIX_AUTH_REQUIRED is true but SYNTRIX_PASSWORD_AUTH is false — "
            "Bearer-protected routes will return 401 until password auth is enabled."
        )


def _decode_password_bearer(token: str) -> Optional[Dict[str, Any]]:
    if not settings.password_auth_enabled:
        return None
    try:
        return decode_access_token(token)
    except JWTError:
        return None


def require_user(
    creds: HTTPAuthorizationCredentials = Depends(_bearer),
) -> AuthenticatedUser:
    if not settings.auth_required:
        return AuthenticatedUser(sub="dev-local-user", email="dev@syntrix.local", raw_claims={})

    if not creds or not creds.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="unauthorized",
        )

    claims = _decode_password_bearer(creds.credentials)
    if not claims:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="unauthorized",
        )

    sub = claims.get("sub")
    if not sub:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized")

    return AuthenticatedUser(sub=sub, email=claims.get("email"), raw_claims=claims)


def optional_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> Optional[AuthenticatedUser]:
    """Valid Bearer JWT → user; missing or invalid token → None (anonymous)."""
    if not creds or not creds.credentials:
        return None
    if not settings.password_auth_enabled:
        return None
    claims = _decode_password_bearer(creds.credentials)
    if not claims:
        return None
    sub = claims.get("sub")
    if not sub:
        return None
    return AuthenticatedUser(sub=sub, email=claims.get("email"), raw_claims=claims)
