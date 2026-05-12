"""
Beyond “has a JWT” — who’s actually allowed to burn scan quota / hit paid surfaces.

Stripe + admin approval flip the ``authorized`` flag in SQLite; these deps enforce that policy
so we’re not confusing “signed up” with “good to go”.
"""

from __future__ import annotations

import secrets

from fastapi import Depends, HTTPException, Request, status

from app.deps import AuthenticatedUser, require_user
from app.config import settings
from app.storage import store


def require_authorized_account(user: AuthenticatedUser = Depends(require_user)) -> AuthenticatedUser:
    """
    Subscription/admin gate: when ``SYNTRIX_REQUIRE_AUTHORIZED_ACCOUNT`` is on, ``users.authorized``
    must be 1 or you get a clear 403 (not a cryptic scan failure later).

    Flag is set by Stripe webhooks or an admin bearer call — see ``GET /api/auth/me`` for state.
    """
    if not settings.require_authorized_account:
        return user
    em = store.canonical_email_for_sub(user.sub, user.email)
    if settings.is_admin_email(em):
        return user
    row = store.get_user(user.sub)
    if row and int(row.get("authorized", 0)) == 1:
        return user
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="This account is not authorized to use Syntrix yet. Complete checkout, ask an admin to approve your email, or contact support.",
    )


def require_admin_bearer(request: Request) -> None:
    """
    Shared secret admin API — ``Authorization: Bearer <SYNTRIX_ADMIN_SECRET>`` or we pretend route doesn’t exist.

    I return 404 when the secret isn’t configured so scanners don’t get a free “admin exists” probe.
    """
    expected = (settings.admin_secret or "").strip()
    if not expected:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    auth = (request.headers.get("authorization") or "").strip()
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    token = auth[7:].strip()
    if not secrets.compare_digest(token, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
