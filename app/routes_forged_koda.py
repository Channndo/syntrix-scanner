"""ForgEd KODA — server-to-server Ollama proxy (same Hetzner host as MIRA).

ForgEd Netlify validates the learner session, then calls these routes with
``X-Forged-Server-Secret`` (same value as ``FORGED_SERVER_SECRET`` on both sides).
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app.config import settings
from app.koda_prompt import KODA_SYSTEM_PROMPT
from app.routes_mira import (
    MiraChatMessage,
    _ollama_chat_stream_aggregate,
    _safe_public_base,
    _sanitize_mira_text,
)

router = APIRouter(tags=["forged-koda"])

_CLIENT_MESSAGE_ROLES = frozenset({"user", "assistant"})
_KODA_MAX_REPLY_CHARS = 48_000


def _require_forged_secret(x_forged_server_secret: Optional[str]) -> None:
    expected = (getattr(settings, "forged_server_secret", None) or "").strip()
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="FORGED_SERVER_SECRET is not configured on this API host.",
        )
    if (x_forged_server_secret or "").strip() != expected:
        raise HTTPException(status_code=401, detail="Invalid ForgEd server secret.")


class ForgedKodaChatBody(BaseModel):
    model_config = ConfigDict(extra="ignore")

    messages: List[MiraChatMessage] = Field(..., min_length=1, max_length=48)
    system_prompt: Optional[str] = Field(default=None, max_length=24_000)


class ForgedKodaChatResponse(BaseModel):
    message: str
    model: str


class ForgedKodaStatusResponse(BaseModel):
    enabled: bool
    model: str
    base_url: str
    cognitive_stack: Optional[str] = None
    assistant: str = "KODA"


@router.get("/status", response_model=ForgedKodaStatusResponse)
def forged_koda_status(
    x_forged_server_secret: Optional[str] = Header(default=None),
):
    """Health for ForgEd — same Ollama stack as MIRA."""
    _require_forged_secret(x_forged_server_secret)
    enabled = bool(settings.koda_enabled and settings.mira_enabled)
    base = (settings.ollama_base_url or "").strip()
    model = (settings.ollama_model or "").strip()
    return ForgedKodaStatusResponse(
        enabled=enabled and bool(base and model),
        model=model or "unset",
        base_url=_safe_public_base(base),
        cognitive_stack="Omnistrata-Ollama" if enabled else None,
        assistant="KODA",
    )


@router.post("/chat", response_model=ForgedKodaChatResponse)
async def forged_koda_chat(
    payload: ForgedKodaChatBody,
    x_forged_server_secret: Optional[str] = Header(default=None),
):
    _require_forged_secret(x_forged_server_secret)
    if not settings.koda_enabled or not settings.mira_enabled:
        raise HTTPException(status_code=503, detail="KODA / MIRA is disabled on this API host.")

    base = (settings.ollama_base_url or "").strip().rstrip("/")
    model = (settings.ollama_model or "").strip()
    if not base or not model:
        raise HTTPException(status_code=503, detail="OLLAMA_BASE_URL or OLLAMA_MODEL is not configured.")

    system_prompt = (payload.system_prompt or "").strip() or KODA_SYSTEM_PROMPT
    ollama_messages: List[Dict[str, Any]] = [{"role": "system", "content": system_prompt}]
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

    request_id = uuid.uuid4().hex[:16]
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

    return ForgedKodaChatResponse(message=content, model=used_model)
