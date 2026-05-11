"""MIRA assistant — proxies chat to a local or remote Ollama server."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Dict, List, Literal, Optional, Tuple

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
    # Render sets RENDER_GIT_COMMIT on deploy — helps verify production picked up latest MIRA code.
    git_commit: Optional[str] = None


def _require_mira_enabled() -> None:
    if not settings.mira_enabled:
        raise HTTPException(
            status_code=503,
            detail="MIRA is disabled on this deployment (set SYNTRIX_MIRA_ENABLED=true).",
        )


@router.get("/status", response_model=MiraStatusResponse)
def mira_status():
    """Public: lets the landing page hide or soften UI when MIRA is off."""
    commit = (os.getenv("RENDER_GIT_COMMIT") or "").strip() or None
    return MiraStatusResponse(
        enabled=bool(settings.mira_enabled),
        model=(settings.ollama_model or "").strip() or "unset",
        base_url=_safe_public_base(settings.ollama_base_url),
        git_commit=commit,
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


async def _ollama_chat_stream_aggregate(
    client: httpx.AsyncClient,
    url: str,
    body: Dict[str, Any],
    headers: Dict[str, str],
    model_fallback: str,
    wall_seconds: float,
) -> Tuple[str, str]:
    """
    Ollama /api/chat with stream=true. httpx read timeout is *per idle gap between chunks*; a long
    time-to-first-token on non-streaming POST counts as one read and trips MIRA on CPU hosts.
    We disable per-read timeout on the stream and cap total wall time with asyncio.wait_for.
    """
    payload = {**body, "stream": True}
    state: Dict[str, Any] = {"model": model_fallback, "parts": []}

    async def _consume() -> None:
        async with client.stream("POST", url, json=payload, headers=headers) as r:
            if r.status_code >= 400:
                raw = (await r.aread()).decode("utf-8", errors="replace")[:800]
                raise HTTPException(
                    status_code=502,
                    detail=f"Model server error: {raw}",
                )
            async for line in r.aiter_lines():
                line = (line or "").strip()
                if not line:
                    continue
                try:
                    obj: Any = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(obj, dict):
                    continue
                mname = obj.get("model")
                if isinstance(mname, str) and mname.strip():
                    state["model"] = mname.strip()
                msg = obj.get("message")
                if isinstance(msg, dict):
                    piece = msg.get("content")
                    if isinstance(piece, str) and piece:
                        state["parts"].append(piece)

    try:
        await asyncio.wait_for(_consume(), timeout=wall_seconds)
    except asyncio.TimeoutError as exc:
        raise HTTPException(
            status_code=504,
            detail=(
                "The language model took too long to respond (stream wall clock). "
                "Try a smaller OLLAMA_MODEL, lower OLLAMA_NUM_CTX, or run Ollama on GPU."
            ),
        ) from exc

    content = "".join(state["parts"]).strip()
    return content, str(state["model"] or model_fallback)


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
    # CPU-only Ollama behind nginx/Render: large n_ctx or num_predict stalls first-token for minutes.
    # Defaults keep MIRA usable; hard caps stop a mis-set OLLAMA_NUM_* on Render from undoing that.
    _ctx = int(settings.ollama_num_ctx) if settings.ollama_num_ctx is not None else 4096
    _pred = int(settings.ollama_num_predict) if settings.ollama_num_predict is not None else 512
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
    # Stream: read=None avoids failing on long gaps *before first token*; wall caps total time.
    # Generous connect/write so Render→user-VPS cold paths do not trip httpx before Ollama streams.
    stream_timeout = httpx.Timeout(connect=90.0, read=None, write=300.0, pool=90.0)
    try:
        async with httpx.AsyncClient(timeout=stream_timeout) as client:
            content, used_model = await _ollama_chat_stream_aggregate(
                client, url, body, ollama_headers, model, wall_seconds=wall
            )
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
                "The language model took too long to respond (HTTP transport). "
                "If this persists, confirm Render deployed latest scanner (GET /api/mira/status → git_commit) "
                "and nginx has proxy_buffering off; detail: "
                + str(exc)[:200]
            ),
        ) from exc

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

    return MiraChatResponse(message=content, model=used_model)
