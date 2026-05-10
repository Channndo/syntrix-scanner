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

import io
import sqlite3
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, EmailStr, Field

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

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
MAX_AVATAR_BYTES = 512 * 1024


class PasswordRegisterBody(BaseModel):
    model_config = ConfigDict(extra="ignore")

    email: EmailStr
    password: str = Field(..., min_length=8, max_length=256)
    first_name: Optional[str] = Field(default=None, max_length=100)
    last_name: Optional[str] = Field(default=None, max_length=100)


class PasswordLoginBody(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=256)


class ProfilePatchBody(BaseModel):
    model_config = ConfigDict(extra="ignore")

    first_name: Optional[str] = Field(default=None, max_length=100)
    last_name: Optional[str] = Field(default=None, max_length=100)
    clear_avatar: bool = False


def _require_password_auth_enabled() -> None:
    if not settings.password_auth_enabled:
        raise HTTPException(
            status_code=403,
            detail=(
                "password authentication is disabled on this API; "
                "set SYNTRIX_PASSWORD_AUTH=true (and redeploy if needed)"
            ),
        )


def _public_id(sub: str) -> str:
    if sub.startswith("local:"):
        return sub[6:]
    return sub


def _me_json(user: AuthenticatedUser, raw_row: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """JSON-safe profile (no avatar bytes)."""
    sub = user.sub
    email = user.email or ""
    claims = user.raw_claims or {}
    role = claims.get("role")
    if role not in ("admin", "user"):
        role = "admin" if settings.is_admin_email(email) else "user"

    has_avatar = bool(raw_row and raw_row.get("avatar_png"))
    fn = ""
    ln = ""
    created_at = None
    if raw_row:
        fn = raw_row.get("first_name") or ""
        ln = raw_row.get("last_name") or ""
        created_at = raw_row.get("created_at")

    return {
        "id": _public_id(sub),
        "email": email,
        "role": role,
        "first_name": fn,
        "last_name": ln,
        "created_at": created_at,
        "has_avatar": has_avatar,
    }


@router.post("/password/register")
async def password_register(request: Request, payload: PasswordRegisterBody):
    _require_password_auth_enabled()
    rate_limit_or_429(client_ip(request))
    em = str(payload.email).strip().lower()
    ph = hash_password(payload.password)
    fn = (payload.first_name or "").strip()[:100]
    ln = (payload.last_name or "").strip()[:100]
    try:
        user = user_store.create_user(em, ph, first_name=fn, last_name=ln)
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
    """Current user profile from password JWT (includes signed role for admin emails)."""
    store.ensure_user(user.sub, user.email or "")
    raw = store.get_user(user.sub)
    return _me_json(user, raw)


@router.patch("/profile")
def patch_profile(payload: ProfilePatchBody, user: AuthenticatedUser = Depends(require_user)):
    store.ensure_user(user.sub, user.email or "")
    row = store.get_user(user.sub) or {}
    fn = row.get("first_name") or ""
    ln = row.get("last_name") or ""
    if payload.first_name is not None:
        fn = payload.first_name.strip()[:100]
    if payload.last_name is not None:
        ln = payload.last_name.strip()[:100]
    store.update_user_names(user.sub, fn, ln)
    if payload.clear_avatar:
        store.clear_user_avatar(user.sub)
    raw = store.get_user(user.sub)
    return _me_json(user, raw)


@router.post("/me/avatar")
async def upload_avatar(
    request: Request,
    user: AuthenticatedUser = Depends(require_user),
    file: UploadFile = File(...),
):
    rate_limit_or_429(client_ip(request))
    data = await file.read()
    if len(data) > MAX_AVATAR_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"PNG must be at most {MAX_AVATAR_BYTES // 1024} KB",
        )
    if len(data) < len(PNG_MAGIC) or not data.startswith(PNG_MAGIC):
        raise HTTPException(status_code=400, detail="file must be a PNG image")

    store.ensure_user(user.sub, user.email or "")
    store.set_user_avatar_png(user.sub, data)
    raw = store.get_user(user.sub)
    return _me_json(user, raw)


@router.get("/me/avatar")
def get_avatar(user: AuthenticatedUser = Depends(require_user)):
    store.ensure_user(user.sub, user.email or "")
    row = store.get_user(user.sub)
    blob = row.get("avatar_png") if row else None
    if not blob:
        raise HTTPException(status_code=404, detail="no avatar")
    return StreamingResponse(io.BytesIO(blob), media_type="image/png")


# Terminal verification after deploy (requires SYNTRIX_PASSWORD_AUTH=true on the API):
#   export API=https://api.syntrix.solutions
#   curl -sS -X POST "$API/api/auth/password/register" -H "Content-Type: application/json" \
#     -d '{"email":"you@example.com","password":"yourpassword"}'
#   export TOKEN=<access_token from JSON>
#   curl -sS -X POST "$API/api/auth/password/login" -H "Content-Type: application/json" \
#     -d '{"email":"you@example.com","password":"yourpassword"}'
#   curl -sS "$API/api/auth/me" -H "Authorization: Bearer $TOKEN"
