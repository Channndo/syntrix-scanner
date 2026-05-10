"""
Password auth routes (mounted at /api/auth).

Smoke tests (set API=https://api.syntrix.solutions and a strong password):

  curl -sS -X POST "$API/api/auth/password/register" -H "Content-Type: application/json" \\
    -d '{"email":"you@example.com","password":"your-password-here"}'

  TOKEN="<paste access_token from register response>"
  curl -sS -X POST "$API/api/auth/password/login" -H "Content-Type: application/json" \\
    -d '{"email":"you@example.com","password":"your-password-here"}'

  curl -sS "$API/api/auth/me" -H "Authorization: Bearer $TOKEN"
"""

from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field

from app.auth import (
    hash_password,
    mint_access_token,
    password_needs_rehash,
    verify_password,
)
from app.auth_rate_limit import client_ip, rate_limit_or_429
from app.config import settings
from app.deps import AuthenticatedUser, require_user
from app.storage import UserStore, store

router = APIRouter(tags=["auth"])
user_store = UserStore(store)


class PasswordRegisterBody(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=256)


class PasswordLoginBody(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=256)


def _require_password_auth_enabled() -> None:
    if not settings.password_auth_enabled:
        raise HTTPException(status_code=404, detail="Not Found")


def _public_id(sub: str) -> str:
    if sub.startswith("local:"):
        return sub[6:]
    return sub


@router.post("/password/register")
async def password_register(request: Request, payload: PasswordRegisterBody):
    _require_password_auth_enabled()
    rate_limit_or_429(client_ip(request))
    em = str(payload.email).strip().lower()
    ph = hash_password(payload.password)
    try:
        user = user_store.create_user(em, ph)
    except ValueError:
        raise HTTPException(status_code=409, detail="email already registered") from None
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="email already registered") from None

    token = mint_access_token(user["user_sub"], user["email"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"id": user["id"], "email": user["email"]},
    }


@router.post("/password/login")
async def password_login(request: Request, payload: PasswordLoginBody):
    _require_password_auth_enabled()
    rate_limit_or_429(client_ip(request))
    row = user_store.get_user_by_email(str(payload.email))
    if not row:
        raise HTTPException(status_code=401, detail="invalid credentials")
    if not verify_password(payload.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="invalid credentials")

    if password_needs_rehash(row["password_hash"]):
        user_store.update_password_hash(row["user_sub"], hash_password(payload.password))

    user_store.ensure_identity(row["user_sub"], row["email"])
    token = mint_access_token(row["user_sub"], row["email"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"id": row["id"], "email": row["email"]},
    }


@router.get("/me")
def auth_me(user: AuthenticatedUser = Depends(require_user)):
    """Current user profile from password JWT."""
    sub = user.sub
    email = user.email or ""
    return {"id": _public_id(sub), "email": email}


# Terminal verification after deploy (requires SYNTRIX_PASSWORD_AUTH=true on the API):
#   export API=https://api.syntrix.solutions
#   curl -sS -X POST "$API/api/auth/password/register" -H "Content-Type: application/json" \
#     -d '{"email":"you@example.com","password":"yourpassword"}'
#   export TOKEN=<access_token from JSON>
#   curl -sS -X POST "$API/api/auth/password/login" -H "Content-Type: application/json" \
#     -d '{"email":"you@example.com","password":"yourpassword"}'
#   curl -sS "$API/api/auth/me" -H "Authorization: Bearer $TOKEN"
