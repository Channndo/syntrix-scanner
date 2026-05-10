"""Auth0 JWT verification helpers for API authorization."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import httpx
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError

from app.auth import decode_access_token, ensure_jwt_secret
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


def maybe_derive_auth0_issuer() -> None:
    """If AUTH0_ISSUER is unset, derive https://{{AUTH0_DOMAIN}}/ (Auth0 canonical tenant)."""

    issuer = (getattr(settings, "auth0_issuer", None) or "").strip()
    if issuer:
        return
    domain = (settings.auth0_domain or "").strip()
    if not domain:
        return
    if domain.lower().startswith("http://") or domain.lower().startswith("https://"):
        base = domain.rstrip("/")
    else:
        base = f"https://{domain.rstrip('/')}"
    settings.auth0_issuer = f"{base}/"


def _required_config_errors() -> list[str]:
    errors: list[str] = []
    if not settings.auth0_domain:
        errors.append("AUTH0_DOMAIN is required when SYNTRIX_AUTH_REQUIRED=true")
    if not settings.auth0_audience:
        errors.append("AUTH0_AUDIENCE is required when SYNTRIX_AUTH_REQUIRED=true")
    if not settings.auth0_issuer:
        errors.append(
            "AUTH0_ISSUER is missing and could not be derived — set AUTH0_DOMAIN or AUTH0_ISSUER explicitly "
            "(custom domains often need AUTH0_ISSUER set to the canonical issuer URL from JWTs)."
        )
    return errors


def validate_password_auth_config() -> None:
    if not settings.password_auth_enabled:
        return
    ensure_jwt_secret()


def validate_auth_config() -> None:
    if not settings.auth_required:
        return
    validate_password_auth_config()
    if getattr(settings, "password_auth_enabled", False):
        # Password-only deployments may omit Auth0 entirely.
        if (settings.auth0_domain or "").strip():
            maybe_derive_auth0_issuer()
            errors = _required_config_errors()
            if errors:
                raise RuntimeError("Invalid auth config: " + "; ".join(errors))
        return
    maybe_derive_auth0_issuer()
    errors = _required_config_errors()
    if errors:
        raise RuntimeError("Invalid auth config: " + "; ".join(errors))


def _try_password_jwt(token: str) -> Optional[Dict[str, Any]]:
    if not getattr(settings, "password_auth_enabled", False):
        return None
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "HS256":
            return None
        return decode_access_token(token)
    except (JWTError, jwt.PyJWTError, ValueError):
        return None


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
            detail=f"Failed to fetch identity JWKS: {exc}",
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
        base_iss = settings.auth0_issuer.rstrip("/")
        issuer_claims = [base_iss, f"{base_iss}/"]

        claims = jwt.decode(
            token,
            key=public_key,
            algorithms=["RS256"],
            audience=settings.auth0_audience,
            issuer=issuer_claims,
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

    claims = _try_password_jwt(creds.credentials)
    if claims:
        sub = claims.get("sub")
        if not sub:
            raise HTTPException(status_code=401, detail="Token missing subject")
        return AuthenticatedUser(sub=sub, email=claims.get("email"), raw_claims=claims)

    claims = _verify_token(creds.credentials)
    sub = claims.get("sub")
    if not sub:
        raise HTTPException(status_code=401, detail="Token missing subject")

    return AuthenticatedUser(sub=sub, email=claims.get("email"), raw_claims=claims)
