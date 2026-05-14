"""
Who’s calling the API — password JWTs only (HS256), no social-login maze.

FastAPI dependencies live here: ``require_user`` for “must be logged in”, ``optional_user`` for
“JWT if you have one, otherwise anonymous”. Keeps route handlers dumb and consistent.
"""

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
    """Decoded JWT identity — ``sub`` is stable; ``email`` may be None on older tokens."""

    sub: str
    email: Optional[str]
    raw_claims: Dict[str, Any]


def validate_password_auth_config() -> None:
    """If password auth is on, make sure we actually have a signing secret worth using."""
    if not settings.password_auth_enabled:
        return
    ensure_jwt_secret()


def validate_auth_config() -> None:
    """Boot-time sanity: password stack + “auth required” flag can’t contradict each other silently."""
    validate_password_auth_config()
    if settings.auth_required and not settings.password_auth_enabled:
        logger.warning(
            "SYNTRIX_AUTH_REQUIRED is true but SYNTRIX_PASSWORD_AUTH is false — "
            "Bearer-protected routes will return 401 until password auth is enabled."
        )


def _decode_password_bearer(token: str) -> Optional[Dict[str, Any]]:
    """Try to parse a Bearer token as our HS256 access JWT; bad/expired → None (no exception leak)."""
    if not settings.password_auth_enabled:
        return None
    try:
        return decode_access_token(token)
    except JWTError:
        return None


def require_user(
    creds: HTTPAuthorizationCredentials = Depends(_bearer),
) -> AuthenticatedUser:
    """
    Hard gate: valid Bearer JWT or 401.

    When ``SYNTRIX_AUTH_REQUIRED`` is off (local dev), I fake a dev user so routes still run.
    """
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
    """
    Soft gate: JWT wins if it’s legit; otherwise None so MIRA (and friends) can stay public.

    MIRA uses this so signed-in users can send a JWT without forcing login for everyone.
    """
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
