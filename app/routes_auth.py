"""
Password auth API — register, login, device trust, profile, the whole boring-but-critical path.

Quick curl cheats (set ``API`` and use a real password):

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
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.responses import StreamingResponse
from jose import JWTError
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

from app.auth import (
    decode_access_token,
    decode_login_challenge_token,
    decode_password_change_session_token,
    device_trust_token_valid,
    hash_password,
    mint_access_token,
    mint_device_trust_token,
    mint_login_challenge_token,
    mint_password_change_session_token,
    normalize_security_answer,
    password_needs_rehash,
    verify_password,
)
from app.auth_rate_limit import client_ip, rate_limit_or_429
from app.config import settings
from app.deps import AuthenticatedUser, require_user
from app.plan_tier import subscription_plan_tier
from app.security_questions import CANNED_SECURITY_QUESTIONS, question_text
from app.storage import UserStore, store

router = APIRouter(tags=["auth"])
user_store = UserStore(store)

_optional_bearer = HTTPBearer(auto_error=False)

PASSWORD_MAX_AGE_DAYS = 90
PASSWORD_HISTORY_SIZE = 24

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
MAX_AVATAR_BYTES = 2 * 1024 * 1024


class PasswordRegisterBody(BaseModel):
    model_config = ConfigDict(extra="ignore")

    email: EmailStr
    password: str = Field(..., min_length=8, max_length=256)
    first_name: Optional[str] = Field(default=None, max_length=100)
    last_name: Optional[str] = Field(default=None, max_length=100)
    security_q1_id: int
    security_q2_id: int
    security_answer1: str = Field(..., min_length=2, max_length=256)
    security_answer2: str = Field(..., min_length=2, max_length=256)

    @field_validator("security_q1_id", "security_q2_id")
    @classmethod
    def question_ids_in_range(cls, v: int) -> int:
        if v < 0 or v >= len(CANNED_SECURITY_QUESTIONS):
            raise ValueError("invalid security question id")
        return v

    @model_validator(mode="after")
    def distinct_questions(self):
        if self.security_q1_id == self.security_q2_id:
            raise ValueError("security questions must be different")
        return self


class PasswordLoginBody(BaseModel):
    model_config = ConfigDict(extra="ignore")

    email: EmailStr
    password: str = Field(..., min_length=8, max_length=256)
    device_trust_token: Optional[str] = Field(default=None, max_length=8192)


class PasswordLoginSecurityBody(BaseModel):
    challenge_token: str = Field(..., min_length=20, max_length=4096)
    answer1: str = Field(..., min_length=1, max_length=256)
    answer2: str = Field(..., min_length=1, max_length=256)
    trust_device: bool = False


class ProfilePatchBody(BaseModel):
    model_config = ConfigDict(extra="ignore")

    first_name: Optional[str] = Field(default=None, max_length=100)
    last_name: Optional[str] = Field(default=None, max_length=100)
    clear_avatar: bool = False


class PasswordChangeBody(BaseModel):
    model_config = ConfigDict(extra="ignore")

    current_password: str = Field(..., min_length=1, max_length=256)
    new_password: str = Field(..., min_length=8, max_length=256)
    change_session_token: Optional[str] = Field(default=None, max_length=8192)


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


def _has_security_questions_row(row: Dict[str, Any]) -> bool:
    return bool(
        row.get("security_a1_hash")
        and row.get("security_a2_hash")
        and row.get("security_q1_id") is not None
        and row.get("security_q2_id") is not None
    )


def _parse_iso_utc(value: Optional[str]) -> Optional[datetime]:
    if not value or not str(value).strip():
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def _password_change_reason(row: Dict[str, Any]) -> Optional[str]:
    """
    Return a reason string if the user must change password before full login, else None.
    Admin force-compromise overrides rotation exempt.
    """
    if row.get("force_password_change"):
        return "admin_required"
    if row.get("password_rotation_exempt"):
        return None
    changed = row.get("password_changed_at") or row.get("created_at")
    dt = _parse_iso_utc(changed)
    if dt is None:
        # Cannot assess age — do not block login (avoid skipping security questions on bad data).
        return None
    age = datetime.now(timezone.utc) - dt
    if age > timedelta(days=PASSWORD_MAX_AGE_DAYS):
        return "rotation_expired"
    return None


def _new_password_reuses_history(
    plain: str, current_hash: str, history_hashes: List[str]
) -> bool:
    if verify_password(plain, current_hash):
        return True
    for prev in history_hashes:
        if verify_password(plain, prev):
            return True
    return False


def _me_json(user: AuthenticatedUser, raw_row: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """JSON-safe profile (no avatar bytes)."""
    sub = user.sub
    email = store.canonical_email_for_sub(sub, user.email)
    role = "admin" if settings.is_admin_email(email) else "user"

    has_avatar = bool(raw_row and raw_row.get("avatar_png"))
    fn = ""
    ln = ""
    created_at = None
    if raw_row:
        fn = raw_row.get("first_name") or ""
        ln = raw_row.get("last_name") or ""
        created_at = raw_row.get("created_at")

    subrec = store.get_subscription(sub)
    admin_unlimited = settings.is_admin_email(email)
    return {
        "id": _public_id(sub),
        "email": email,
        "role": role,
        "scanner_unlimited": admin_unlimited,
        "first_name": fn,
        "last_name": ln,
        "created_at": created_at,
        "has_avatar": has_avatar,
        "subscription": {
            "status": subrec.get("status") or "inactive",
            "plan_id": subrec.get("plan_id"),
            "plan_tier": subscription_plan_tier(subrec),
            "current_period_end": subrec.get("current_period_end"),
            "billing_exempt": admin_unlimited,
        },
    }


@router.post("/password/register")
async def password_register(request: Request, payload: PasswordRegisterBody):
    _require_password_auth_enabled()
    rate_limit_or_429(client_ip(request))
    em = str(payload.email).strip().lower()
    ph = hash_password(payload.password)
    fn = (payload.first_name or "").strip()[:100]
    ln = (payload.last_name or "").strip()[:100]
    h1 = hash_password(normalize_security_answer(payload.security_answer1))
    h2 = hash_password(normalize_security_answer(payload.security_answer2))
    try:
        user = user_store.create_user(
            em,
            ph,
            first_name=fn,
            last_name=ln,
            security_q1_id=payload.security_q1_id,
            security_q2_id=payload.security_q2_id,
            security_a1_hash=h1,
            security_a2_hash=h2,
        )
    except ValueError:
        raise HTTPException(status_code=409, detail="email already registered") from None
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="email already registered") from None

    token = mint_access_token(user["user_sub"], user["email"])
    out: Dict[str, Any] = {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "email": user["email"],
            "role": "admin" if settings.is_admin_email(em) else "user",
            "scanner_unlimited": settings.is_admin_email(em),
        },
    }
    if settings.is_admin_email(em):
        out["account_message"] = (
            "This is the sole operator account. You have unlimited authenticated scans without "
            "a paid subscription, including when billing is required for other users."
        )
    return out


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
    pa = store.get_password_account_by_sub(row["user_sub"])
    if not pa:
        raise HTTPException(status_code=401, detail="invalid credentials")

    # New / unrecognized browsers must answer security questions *before* rotation/password-change.
    # Trusted devices skip SQ, then we enforce rotation if needed.
    if _has_security_questions_row(pa):
        if device_trust_token_valid(
            payload.device_trust_token,
            pa["user_sub"],
            pa["email"],
        ):
            rotate_reason = _password_change_reason(pa)
            if rotate_reason:
                return {
                    "password_change_required": True,
                    "reason": rotate_reason,
                    "change_session_token": mint_password_change_session_token(
                        pa["user_sub"], pa["email"]
                    ),
                    "user": {"id": row["id"], "email": row["email"]},
                }
            token = mint_access_token(pa["user_sub"], pa["email"])
            return {
                "access_token": token,
                "token_type": "bearer",
                "user": {"id": row["id"], "email": row["email"]},
                "trusted_device": True,
            }
        q1 = int(pa["security_q1_id"])
        q2 = int(pa["security_q2_id"])
        challenge = mint_login_challenge_token(pa["user_sub"], pa["email"])
        return {
            "requires_security_questions": True,
            "challenge_token": challenge,
            "questions": [
                {"id": q1, "text": question_text(q1)},
                {"id": q2, "text": question_text(q2)},
            ],
        }

    rotate_reason = _password_change_reason(pa)
    if rotate_reason:
        return {
            "password_change_required": True,
            "reason": rotate_reason,
            "change_session_token": mint_password_change_session_token(pa["user_sub"], pa["email"]),
            "user": {"id": row["id"], "email": row["email"]},
        }

    token = mint_access_token(pa["user_sub"], pa["email"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"id": row["id"], "email": row["email"]},
    }


@router.post("/password/login/security")
async def password_login_security(request: Request, payload: PasswordLoginSecurityBody):
    _require_password_auth_enabled()
    rate_limit_or_429(client_ip(request))
    try:
        claims = decode_login_challenge_token(payload.challenge_token)
    except (JWTError, ValueError):
        raise HTTPException(status_code=401, detail="invalid or expired challenge") from None

    user_sub = claims.get("sub")
    email_claim = (claims.get("email") or "").strip().lower()
    if not user_sub or not email_claim:
        raise HTTPException(status_code=401, detail="invalid challenge")

    row = store.get_password_account_by_sub(str(user_sub))
    if not row or (row.get("email") or "").strip().lower() != email_claim:
        raise HTTPException(status_code=401, detail="invalid challenge")

    if not _has_security_questions_row(row):
        raise HTTPException(status_code=400, detail="security questions not configured for this account")

    a1ok = verify_password(
        normalize_security_answer(payload.answer1),
        str(row["security_a1_hash"]),
    )
    a2ok = verify_password(
        normalize_security_answer(payload.answer2),
        str(row["security_a2_hash"]),
    )
    if not a1ok or not a2ok:
        raise HTTPException(status_code=401, detail="incorrect security answers")

    user_store.ensure_identity(user_sub, row["email"])
    rotate_reason = _password_change_reason(row)
    if rotate_reason:
        return {
            "password_change_required": True,
            "reason": rotate_reason,
            "change_session_token": mint_password_change_session_token(
                str(user_sub), str(row["email"])
            ),
            "user": {"id": _public_id(str(user_sub)), "email": row["email"]},
        }

    token = mint_access_token(user_sub, row["email"])
    out: Dict[str, Any] = {
        "access_token": token,
        "token_type": "bearer",
        "user": {"id": _public_id(user_sub), "email": row["email"]},
    }
    if payload.trust_device:
        out["device_trust_token"] = mint_device_trust_token(user_sub, row["email"])
    return out


@router.post("/password/change")
async def password_change(
    request: Request,
    payload: PasswordChangeBody,
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_optional_bearer),
):
    """Change password (forced rotation or voluntary). Accepts change_session_token or Bearer JWT."""
    _require_password_auth_enabled()
    rate_limit_or_429(client_ip(request))

    user_sub: Optional[str] = None
    email_claim: Optional[str] = None
    tok = (payload.change_session_token or "").strip()
    if tok:
        try:
            claims = decode_password_change_session_token(tok)
        except (JWTError, ValueError):
            raise HTTPException(
                status_code=401,
                detail="invalid or expired password-change session",
            ) from None
        user_sub = claims.get("sub")
        email_claim = (claims.get("email") or "").strip().lower()
    elif creds and creds.credentials:
        try:
            claims = decode_access_token(creds.credentials)
        except JWTError:
            raise HTTPException(status_code=401, detail="unauthorized") from None
        user_sub = claims.get("sub")
        email_claim = (claims.get("email") or "").strip().lower()
    else:
        raise HTTPException(
            status_code=401,
            detail="change_session_token or Authorization bearer required",
        )

    if not user_sub:
        raise HTTPException(status_code=401, detail="unauthorized")

    acct = store.get_password_account_by_sub(str(user_sub))
    if not acct:
        raise HTTPException(status_code=404, detail="account not found")
    em = (acct.get("email") or "").strip().lower()
    if email_claim and em != email_claim:
        raise HTTPException(status_code=401, detail="invalid session")

    if not verify_password(payload.current_password, acct["password_hash"]):
        raise HTTPException(status_code=401, detail="incorrect current password")

    hist = store.list_password_history_hashes(str(user_sub), limit=PASSWORD_HISTORY_SIZE)
    if _new_password_reuses_history(payload.new_password, acct["password_hash"], hist):
        raise HTTPException(
            status_code=400,
            detail="password_reused",
        )

    new_hash = hash_password(payload.new_password)
    store.replace_password_with_history(str(user_sub), str(acct["password_hash"]), new_hash)

    token = mint_access_token(str(user_sub), em)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"id": _public_id(str(user_sub)), "email": em},
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
        mb = MAX_AVATAR_BYTES // (1024 * 1024)
        raise HTTPException(
            status_code=413,
            detail=f"PNG must be at most {mb} MB",
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
