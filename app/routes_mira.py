"""MIRA assistant — proxies chat to a local or remote Ollama server."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Literal, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from app.auth_rate_limit import client_ip, rate_limit_or_429
from app.config import settings
from app.deps import AuthenticatedUser, optional_user
from app.mira_prompt import MIRA_SYSTEM_PROMPT
from app.storage import store

logger = logging.getLogger(__name__)

router = APIRouter(tags=["mira"])

_ALLOWED_ROLES = frozenset({"user", "assistant", "system"})


class MiraChatMessage(BaseModel):
    model_config = ConfigDict(extra="ignore")

    role: Literal["user", "assistant", "system"]
    content: str = Field(..., min_length=1, max_length=12000)


class MiraChatBody(BaseModel):
    model_config = ConfigDict(extra="ignore")

    messages: List[MiraChatMessage] = Field(..., min_length=1, max_length=48)


class MiraChatResponse(BaseModel):
    message: str
    model: str


class MiraStatusResponse(BaseModel):
    enabled: bool
    model: str
    base_url: str


def _require_mira_enabled() -> None:
    if not settings.mira_enabled:
        raise HTTPException(
            status_code=503,
            detail="MIRA is disabled on this deployment (set SYNTRIX_MIRA_ENABLED=true).",
        )


@router.get("/status", response_model=MiraStatusResponse)
def mira_status():
    """Public: lets the landing page hide or soften UI when MIRA is off."""
    return MiraStatusResponse(
        enabled=bool(settings.mira_enabled),
        model=(settings.ollama_model or "").strip() or "unset",
        base_url=_safe_public_base(settings.ollama_base_url),
    )


def _safe_public_base(url: str) -> str:
    """Avoid leaking credentials in host string (best-effort)."""
    u = (url or "").strip().rstrip("/")
    if "@" in u.split("://", 1)[-1]:
        return "(redacted)"
    return u or "(unset)"


def _last_user_text(messages: List[MiraChatMessage]) -> str:
    for m in reversed(messages):
        if m.role == "user":
            return m.content.strip()
    return ""


def _system_prompt_for_user(user: Optional[AuthenticatedUser]) -> str:
    if not user:
        return MIRA_SYSTEM_PROMPT
    memory = store.get_mira_user_memory(user.sub).strip()
    if not memory:
        return MIRA_SYSTEM_PROMPT
    return (
        MIRA_SYSTEM_PROMPT
        + "\n\n---\nContext from this user's prior MIRA conversations (stay consistent; "
        "do not quote or reveal storage details):\n"
        + memory
    )


@router.post("/chat", response_model=MiraChatResponse)
async def mira_chat(
    request: Request,
    payload: MiraChatBody,
    user: Optional[AuthenticatedUser] = Depends(optional_user),
):
    """
    Chat via Ollama `/api/chat`. Open to anonymous users; optional Bearer JWT for per-user memory.
    Configure OLLAMA_BASE_URL and OLLAMA_MODEL on the API host.
    """
    _require_mira_enabled()
    rate_limit_or_429(client_ip(request))

    base = (settings.ollama_base_url or "").strip().rstrip("/")
    model = (settings.ollama_model or "").strip()
    if not base:
        raise HTTPException(
            status_code=503,
            detail="OLLAMA_BASE_URL is not configured on this API.",
        )
    if not model:
        raise HTTPException(
            status_code=503,
            detail="OLLAMA_MODEL is not configured on this API.",
        )

    ollama_messages: List[Dict[str, Any]] = [{"role": "system", "content": _system_prompt_for_user(user)}]
    for m in payload.messages:
        if m.role not in _ALLOWED_ROLES:
            continue
        ollama_messages.append({"role": m.role, "content": m.content})

    url = f"{base}/api/chat"
    options: Dict[str, Any] = {"temperature": float(settings.ollama_temperature)}
    # When unset, Ollama uses model defaults (often a very large n_ctx), which is extremely slow on
    # CPU-only hosts and routinely trips MIRA's HTTP read timeout. Prefer bounded work unless tuned.
    options["num_ctx"] = (
        int(settings.ollama_num_ctx) if settings.ollama_num_ctx is not None else 8192
    )
    options["num_predict"] = (
        int(settings.ollama_num_predict) if settings.ollama_num_predict is not None else 1024
    )
    body = {
        "model": model,
        "messages": ollama_messages,
        "stream": False,
        "options": options,
    }

    ollama_headers: Dict[str, str] = {}
    if settings.ollama_api_key:
        ollama_headers["Authorization"] = f"Bearer {settings.ollama_api_key}"

    read_timeout = max(30.0, float(settings.ollama_http_timeout_seconds))
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=20.0, read=read_timeout, write=read_timeout, pool=30.0
            )
        ) as client:
            r = await client.post(url, json=body, headers=ollama_headers)
    except httpx.ConnectError as exc:
        logger.warning("MIRA Ollama connect failed: %s", exc)
        raise HTTPException(
            status_code=503,
            detail="Could not reach the language model server. Check OLLAMA_BASE_URL and network access.",
        ) from exc
    except httpx.TimeoutException as exc:
        raise HTTPException(
            status_code=504,
            detail=(
                "The language model took too long to respond. Try a shorter question, "
                "or lower OLLAMA_NUM_CTX / OLLAMA_NUM_PREDICT on the API host for CPU-only Ollama."
            ),
        ) from exc

    if r.status_code >= 400:
        detail = r.text[:500]
        try:
            err_json = r.json()
            if isinstance(err_json, dict) and err_json.get("error"):
                detail = str(err_json["error"])[:500]
        except Exception:
            pass
        logger.warning("Ollama error %s: %s", r.status_code, detail)
        raise HTTPException(
            status_code=502,
            detail=f"Model server error: {detail}",
        )

    try:
        data = r.json()
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Invalid response from model server.") from exc

    msg = data.get("message") or {}
    content = (msg.get("content") or "").strip()
    if not content:
        raise HTTPException(status_code=502, detail="Empty reply from model.")

    if user:
        u_text = _last_user_text(payload.messages)
        if u_text:
            try:
                store.ensure_user(user.sub, user.email)
                store.append_mira_user_memory(user.sub, u_text, content)
            except Exception:
                logger.exception("MIRA user memory update failed for sub=%s", user.sub)

    return MiraChatResponse(message=content, model=str(data.get("model") or model))
