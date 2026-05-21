"""KODA HTTP surface — ForgEd learning assistant (same Ollama host as MIRA)."""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from app.auth_rate_limit import client_ip, mira_rate_limit_or_429
from app.config import settings
from app.deps import AuthenticatedUser, require_user
from app.koda_prompt import KODA_SYSTEM_PROMPT
from app.routes_mira import (
    MiraChatMessage,
    _ollama_chat_stream_aggregate,
    _safe_public_base,
    _sanitize_mira_text,
)

router = APIRouter(tags=["koda"])

_CLIENT_MESSAGE_ROLES = frozenset({"user", "assistant"})
_KODA_MAX_REPLY_CHARS = 48_000


class KodaChatBody(BaseModel):
    model_config = ConfigDict(extra="ignore")

    messages: List[MiraChatMessage] = Field(..., min_length=1, max_length=48)
    mode: Optional[str] = None


class KodaChatResponse(BaseModel):
    message: str
    model: str


class KodaStatusResponse(BaseModel):
    enabled: bool
    model: str
    base_url: str
    cognitive_stack: Optional[str] = None
    assistant: str = "KODA"


def _require_koda_enabled() -> None:
    if not settings.koda_enabled:
        raise HTTPException(
            status_code=503,
            detail="KODA is disabled on this deployment (set SYNTRIX_KODA_ENABLED=true).",
        )


@router.get("/status", response_model=KodaStatusResponse)
def koda_status():
    """Public health for ForgEd — whether KODA + Ollama are configured (no JWT required)."""
    enabled = bool(settings.koda_enabled and settings.mira_enabled)
    return KodaStatusResponse(
        enabled=enabled,
        model=(settings.ollama_model or "").strip() or "unset",
        base_url=_safe_public_base(settings.ollama_base_url),
        cognitive_stack="Omnistrata-Ollama" if enabled else None,
        assistant="KODA",
    )


@router.post("/chat", response_model=KodaChatResponse)
async def koda_chat(
    request: Request,
    payload: KodaChatBody,
    user: AuthenticatedUser = Depends(require_user),
):
    """Signed-in chat only — same JWT as MIRA; uses KODA educational system prompt."""
    _require_koda_enabled()
    if not settings.mira_enabled:
        raise HTTPException(status_code=503, detail="AI stack is disabled on this API host.")

    request_id = uuid.uuid4().hex[:16]
    ip = client_ip(request)
    mira_rate_limit_or_429(
        ip,
        settings.mira_rate_max_requests,
        settings.mira_rate_window_sec,
    )

    base = (settings.ollama_base_url or "").strip().rstrip("/")
    model = (settings.ollama_model or "").strip()
    if not base or not model:
        raise HTTPException(status_code=503, detail="OLLAMA_BASE_URL or OLLAMA_MODEL is not configured.")

    ollama_messages: List[Dict[str, Any]] = [{"role": "system", "content": KODA_SYSTEM_PROMPT}]
    for m in payload.messages:
        if m.role not in _CLIENT_MESSAGE_ROLES:
            continue
        piece = _sanitize_mira_text(m.content)
        if not piece:
            continue
        ollama_messages.append({"role": m.role, "content": piece})

    if len(ollama_messages) < 2:
        raise HTTPException(status_code=400, detail="A user message is required.")

    url = f"{base}/api/chat"
    options: Dict[str, Any] = {"temperature": float(settings.ollama_temperature)}
    _ctx = int(settings.ollama_num_ctx) if settings.ollama_num_ctx is not None else 4096
    _pred = int(settings.ollama_num_predict) if settings.ollama_num_predict is not None else 768
    options["num_ctx"] = min(max(512, _ctx), 8192)
    options["num_predict"] = min(max(64, _pred), 2048)
    body: Dict[str, Any] = {
        "model": model,
        "messages": ollama_messages,
        "options": options,
    }

    ollama_headers: Dict[str, str] = {}
    if settings.ollama_api_key:
        ollama_headers["Authorization"] = f"Bearer {settings.ollama_api_key}"

    wall = max(120.0, float(settings.ollama_http_timeout_seconds)) + 60.0
    stream_timeout = httpx.Timeout(connect=90.0, read=None, write=300.0, pool=90.0)
    try:
        async with httpx.AsyncClient(timeout=stream_timeout) as client:
            content, used_model, _metrics = await _ollama_chat_stream_aggregate(
                client,
                url,
                body,
                ollama_headers,
                model,
                wall,
                request_id=request_id,
            )
    except httpx.ConnectError as exc:
        raise HTTPException(
            status_code=503,
            detail="Could not reach the language model server. Check OLLAMA_BASE_URL.",
        ) from exc
    except httpx.TimeoutException as exc:
        raise HTTPException(status_code=504, detail="KODA timed out waiting for the model.") from exc

    if not content:
        raise HTTPException(status_code=502, detail="Empty reply from model.")

    if len(content) > _KODA_MAX_REPLY_CHARS:
        tail = "\n\n[Reply truncated for size limits.]"
        content = content[: _KODA_MAX_REPLY_CHARS - len(tail)] + tail

    return KodaChatResponse(message=content, model=used_model)
