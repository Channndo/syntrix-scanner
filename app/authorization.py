"""Account-level authorization (who may use the product beyond having a valid JWT)."""

from __future__ import annotations

import secrets

from fastapi import Depends, HTTPException, Request, status

from app.deps import AuthenticatedUser, require_user
from app.config import settings
from app.storage import store


def require_authorized_account(user: AuthenticatedUser = Depends(require_user)) -> AuthenticatedUser:
    """
    When SYNTRIX_REQUIRE_AUTHORIZED_ACCOUNT=true, only users with users.authorized=1
    may call routes protected by this dependency. Stripe active subscriptions and
    admin approval set the flag; see /api/auth/me.
    """
    if not settings.require_authorized_account:
        return user
    row = store.get_user(user.sub)
    if row and int(row.get("authorized", 0)) == 1:
        return user
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="This account is not authorized to use Syntrix yet. Complete checkout, ask an admin to approve your email, or contact support.",
    )


def require_admin_bearer(request: Request) -> None:
    expected = (settings.admin_secret or "").strip()
    if not expected:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    auth = (request.headers.get("authorization") or "").strip()
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    token = auth[7:].strip()
    if not secrets.compare_digest(token, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
