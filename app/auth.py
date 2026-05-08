"""Auth0 JWT verification helpers for API authorization."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import httpx
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import settings


_bearer = HTTPBearer(auto_error=False)
_jwks_cache: Optional[Dict[str, Any]] = None
_jwks_cached_until: Optional[datetime] = None
_JWKS_TTL_SECONDS = 300


@dataclass
class AuthenticatedUser:
    sub: str
    email: Optional[str]
    raw_claims: Dict[str, Any]


def _required_config_errors() -> list[str]:
    errors: list[str] = []
    if not settings.auth0_domain:
        errors.append("AUTH0_DOMAIN is required when SYNTRIX_AUTH_REQUIRED=true")
    if not settings.auth0_audience:
        errors.append("AUTH0_AUDIENCE is required when SYNTRIX_AUTH_REQUIRED=true")
    if not settings.auth0_issuer:
        errors.append("AUTH0_ISSUER is required when SYNTRIX_AUTH_REQUIRED=true")
    return errors


def validate_auth_config() -> None:
    if not settings.auth_required:
        return
    errors = _required_config_errors()
    if errors:
        raise RuntimeError("Invalid auth config: " + "; ".join(errors))


def _resolve_jwks_url() -> str:
    if settings.auth0_jwks_url:
        return settings.auth0_jwks_url
    issuer = settings.auth0_issuer.rstrip("/")
    return f"{issuer}/.well-known/jwks.json"


def _get_jwks() -> Dict[str, Any]:
    global _jwks_cache, _jwks_cached_until

    now = datetime.now(timezone.utc)
    if _jwks_cache and _jwks_cached_until and now < _jwks_cached_until:
        return _jwks_cache

    try:
        r = httpx.get(_resolve_jwks_url(), timeout=5.0)
        r.raise_for_status()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Failed to fetch Auth0 JWKS: {exc}",
        ) from exc

    _jwks_cache = r.json()
    _jwks_cached_until = now + timedelta(seconds=_JWKS_TTL_SECONDS)
    return _jwks_cache


def _select_jwk(kid: str) -> Dict[str, Any]:
    jwks = _get_jwks()
    keys = jwks.get("keys", [])
    for key in keys:
        if key.get("kid") == kid:
            return key
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token key ID not found in JWKS",
    )


def _verify_token(token: str) -> Dict[str, Any]:
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid:
            raise HTTPException(status_code=401, detail="Missing token key ID")
        jwk = _select_jwk(kid)
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
        claims = jwt.decode(
            token,
            key=public_key,
            algorithms=["RS256"],
            audience=settings.auth0_audience,
            issuer=settings.auth0_issuer.rstrip("/"),
        )
        return claims
    except HTTPException:
        raise
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid access token: {exc}",
        ) from exc


def require_user(
    creds: HTTPAuthorizationCredentials = Depends(_bearer),
) -> AuthenticatedUser:
    if not settings.auth_required:
        return AuthenticatedUser(sub="dev-local-user", email="dev@syntrix.local", raw_claims={})

    if not creds or not creds.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )

    claims = _verify_token(creds.credentials)
    sub = claims.get("sub")
    if not sub:
        raise HTTPException(status_code=401, detail="Token missing subject")

    return AuthenticatedUser(sub=sub, email=claims.get("email"), raw_claims=claims)
