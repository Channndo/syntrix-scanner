"""MIRA HTTP surface — chat proxy to Ollama.

The browser never talks to Ollama directly; this module does. I strip sketchy control characters,
ignore client-injected ``system`` turns, and emit ``mira_obs`` lines for latency/abuse metrics
without logging raw prompts. Messages are text-only (paste findings); file uploads are not accepted.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Literal, Optional, Tuple

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.auth_rate_limit import client_ip, mira_rate_limit_or_429
from app.config import settings
from app.mira_obs import mira_obs
from app.deps import AuthenticatedUser, optional_user
from app.mira_prompt import MIRA_SYSTEM_PROMPT
from app.storage import store

logger = logging.getLogger(__name__)

router = APIRouter(tags=["mira"])

_MONTH_ABBR = (
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
)


def _mira_anonymous_daily_limit_detail(limit: int) -> str:
    """Human-readable 429 copy: next UTC midnight (Claude-style “resets at …”)."""
    now = datetime.now(timezone.utc)
    reset = datetime(now.year, now.month, now.day, tzinfo=timezone.utc) + timedelta(days=1)
    m = _MONTH_ABBR[reset.month - 1]
    reset_line = f"{m} {reset.day}, {reset.year} at 00:00 UTC"
    return (
        f"Rate limit reached · Resets {reset_line} · "
        f"Sign in for higher limits ({limit} anonymous messages per UTC day)."
    )

# Roles the *client* may send. We inject the real system prompt server-side; client "system"
# turns are ignored so they cannot sit beside or override our system message in the model API.
_CLIENT_MESSAGE_ROLES = frozenset({"user", "assistant"})


def _sanitize_mira_text(text: str) -> str:
    """
    Strip NULs and C0 control characters (keep tab/newline/CR).

    This is hygiene, not magic — it won’t stop a determined prompt injection, but it keeps logs and
    downstream parsers from choking on garbage bytes pasted from a terminal.
    """
    if not text:
        return ""
    t = text.replace("\x00", "").replace("\ufeff", "")
    return "".join(
        ch for ch in t if ch in "\t\n\r" or (ord(ch) >= 32 and ord(ch) != 127)
    )


class MiraChatMessage(BaseModel):
    """One chat turn from the client — only ``user`` / ``assistant`` are honored (``system`` ignored server-side)."""

    model_config = ConfigDict(extra="ignore")

    role: Literal["user", "assistant", "system"]
    content: str = Field(..., min_length=1, max_length=12000)


class MiraChatBody(BaseModel):
    """POST /chat JSON — text transcript only. ``attachments`` are rejected (paste content instead)."""

    model_config = ConfigDict(extra="ignore")

    messages: List[MiraChatMessage] = Field(..., min_length=1, max_length=48)

    @model_validator(mode="before")
    @classmethod
    def _reject_file_uploads(cls, data: Any) -> Any:
        if isinstance(data, dict):
            att = data.get("attachments")
            if att:
                raise ValueError(
                    "MIRA does not accept file or image uploads. Paste scan findings or questions as text."
                )
            return {k: v for k, v in data.items() if k != "attachments"}
        return data


class MiraChatResponse(BaseModel):
    """What the UI renders — assistant text plus the model name Ollama actually used."""

    message: str
    model: str


class MiraStatusResponse(BaseModel):
    """Public health-ish payload for the marketing site to decide whether to show MIRA."""

    enabled: bool
    model: str
    base_url: str
    # Render sets RENDER_GIT_COMMIT on deploy — helps verify production picked up latest MIRA code.
    git_commit: Optional[str] = None
    # Named internal cognition substrate for MIRA (quiet architecture signal for integrators).
    cognitive_stack: Optional[str] = None


def _require_mira_enabled() -> None:
    """503 if SYNTRIX_MIRA_ENABLED is off — keeps misconfigured deploys from silently burning Ollama."""
    if not settings.mira_enabled:
        raise HTTPException(
            status_code=503,
            detail="MIRA is disabled on this deployment (set SYNTRIX_MIRA_ENABLED=true).",
        )


@router.get("/status", response_model=MiraStatusResponse)
def mira_status():
    """
    Lightweight status for the landing page — model name, whether MIRA is on, redacted Ollama base.

    ``git_commit`` is there so I can prove Render picked up the build I think it picked up.
    """
    commit = (os.getenv("RENDER_GIT_COMMIT") or "").strip() or None
    enabled = bool(settings.mira_enabled)
    return MiraStatusResponse(
        enabled=enabled,
        model=(settings.ollama_model or "").strip() or "unset",
        base_url=_safe_public_base(settings.ollama_base_url),
        git_commit=commit,
        cognitive_stack="Mindroot" if enabled else None,
    )


def _safe_public_base(url: str) -> str:
    """Strip userinfo from URLs before we echo ``base_url`` to browsers — no leaked creds in JSON."""
    u = (url or "").strip().rstrip("/")
    if "@" in u.split("://", 1)[-1]:
        return "(redacted)"
    return u or "(unset)"


_MIRA_MAX_REPLY_CHARS = 48_000


async def _ollama_chat_stream_aggregate(
    client: httpx.AsyncClient,
    url: str,
    body: Dict[str, Any],
    headers: Dict[str, str],
    model_fallback: str,
    wall_seconds: float,
    *,
    request_id: str = "",
) -> Tuple[str, str, Dict[str, Any]]:
    """
    Stream Ollama ``/api/chat`` and stitch assistant ``message.content`` chunks into one reply.

    httpx ``read`` timeout is idle-gap based, so we lean on ``asyncio.wait_for`` for a hard wall clock.
    Side channel: fill ``first_token_ms`` / ``upstream_wall_ms`` for ``mira_obs`` — still zero prompt logging.
    """
    payload = {**body, "stream": True}
    state: Dict[str, Any] = {"model": model_fallback, "parts": []}
    timing_meta: Dict[str, Any] = {}
    t_upstream_start = time.perf_counter()

    async def _consume() -> None:
        async with client.stream("POST", url, json=payload, headers=headers) as r:
            if r.status_code >= 400:
                raw = (await r.aread()).decode("utf-8", errors="replace")[:800]
                elapsed_ms = round((time.perf_counter() - t_upstream_start) * 1000, 3)
                mira_obs(
                    "mira_ollama_http_error",
                    request_id=request_id or None,
                    status_code=r.status_code,
                    upstream_ms=elapsed_ms,
                    error_body_chars=len(raw),
                )
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
                        if "first_token_ms" not in timing_meta:
                            timing_meta["first_token_ms"] = round(
                                (time.perf_counter() - t_upstream_start) * 1000,
                                3,
                            )
                        state["parts"].append(piece)

    try:
        await asyncio.wait_for(_consume(), timeout=wall_seconds)
    except asyncio.TimeoutError as exc:
        elapsed_ms = round((time.perf_counter() - t_upstream_start) * 1000, 3)
        mira_obs(
            "mira_ollama_stream_wall_timeout",
            request_id=request_id or None,
            upstream_ms=elapsed_ms,
            wall_seconds=round(wall_seconds, 3),
        )
        raise HTTPException(
            status_code=504,
            detail=(
                "The language model took too long to respond (stream wall clock). "
                "Try a smaller OLLAMA_MODEL, lower OLLAMA_NUM_CTX, or run Ollama on GPU."
            ),
        ) from exc

    timing_meta["upstream_wall_ms"] = round(
        (time.perf_counter() - t_upstream_start) * 1000,
        3,
    )
    content = "".join(state["parts"]).strip()
    used_model = str(state["model"] or model_fallback)
    metrics: Dict[str, Any] = {
        "upstream_wall_ms": timing_meta.get("upstream_wall_ms"),
        "first_token_ms": timing_meta.get("first_token_ms"),
        "model": used_model,
    }
    return content, used_model, metrics


@router.post("/chat", response_model=MiraChatResponse)
async def mira_chat(
    request: Request,
    payload: MiraChatBody,
    user: Optional[AuthenticatedUser] = Depends(optional_user),
):
    """
    Public chat endpoint — optional JWT. Text-only (paste findings); uploads are not supported.

    Flow: sliding rate limit → anonymous UTC-day cap → build Ollama messages → stream model →
    emit ``mira_obs`` success line.
    """
    _require_mira_enabled()
    request_id = uuid.uuid4().hex[:16]
    ip = client_ip(request)
    t_handler_start = time.perf_counter()
    mira_rate_limit_or_429(
        ip,
        settings.mira_rate_max_requests,
        settings.mira_rate_window_sec,
    )
    if not user:
        if not store.try_acquire_mira_anonymous_daily_chat(ip):
            lim = max(0, int(settings.mira_anonymous_max_per_utc_day))
            mira_obs(
                "mira_anonymous_daily_cap",
                request_id=request_id,
                ip=ip,
                limit=lim,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=_mira_anonymous_daily_limit_detail(lim),
            )

    client_chars = sum(len(m.content) for m in payload.messages)
    prep_ms = round((time.perf_counter() - t_handler_start) * 1000, 3)
    mira_obs(
        "mira_chat_start",
        request_id=request_id,
        ip=ip,
        authed=bool(user),
        messages=len(payload.messages),
        client_chars=client_chars,
        attachments=0,
        attach_bytes=0,
        attach_image=0,
        attach_pdf=0,
        attach_text=0,
        prep_ms_before_upstream=prep_ms,
        cognitive_stack="Mindroot",
    )

    base = (settings.ollama_base_url or "").strip().rstrip("/")
    model = (settings.ollama_model or "").strip()
    if not base:
        mira_obs(
            "mira_chat_config_error",
            request_id=request_id,
            reason="ollama_base_missing",
        )
        raise HTTPException(
            status_code=503,
            detail="OLLAMA_BASE_URL is not configured on this API.",
        )
    if not model:
        mira_obs(
            "mira_chat_config_error",
            request_id=request_id,
            reason="ollama_model_missing",
        )
        raise HTTPException(
            status_code=503,
            detail="OLLAMA_MODEL is not configured on this API.",
        )

    ollama_messages: List[Dict[str, Any]] = [{"role": "system", "content": MIRA_SYSTEM_PROMPT}]
    for m in payload.messages:
        if m.role not in _CLIENT_MESSAGE_ROLES:
            continue
        piece = _sanitize_mira_text(m.content)
        if not piece:
            continue
        ollama_messages.append({"role": m.role, "content": piece})

    if len(ollama_messages) < 2:
        raise HTTPException(
            status_code=400,
            detail="No usable user/assistant content after sanitization.",
        )

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
    t_upstream_mark = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=stream_timeout) as client:
            content, used_model, upstream_metrics = await _ollama_chat_stream_aggregate(
                client,
                url,
                body,
                ollama_headers,
                model,
                wall,
                request_id=request_id,
            )
    except httpx.ConnectError as exc:
        fail_ms = round((time.perf_counter() - t_upstream_mark) * 1000, 3)
        mira_obs(
            "mira_chat_upstream_connect_error",
            request_id=request_id,
            ip=ip,
            upstream_ms=fail_ms,
            err_type=type(exc).__name__,
        )
        raise HTTPException(
            status_code=503,
            detail="Could not reach the language model server. Check OLLAMA_BASE_URL and network access.",
        ) from exc
    except httpx.TimeoutException as exc:
        fail_ms = round((time.perf_counter() - t_upstream_mark) * 1000, 3)
        mira_obs(
            "mira_chat_upstream_transport_timeout",
            request_id=request_id,
            ip=ip,
            upstream_ms=fail_ms,
            detail=str(exc)[:200],
        )
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
        mira_obs(
            "mira_chat_empty_reply",
            request_id=request_id,
            ip=ip,
            upstream_wall_ms=upstream_metrics.get("upstream_wall_ms"),
            first_token_ms=upstream_metrics.get("first_token_ms"),
        )
        raise HTTPException(status_code=502, detail="Empty reply from model.")

    if len(content) > _MIRA_MAX_REPLY_CHARS:
        tail = "\n\n[Reply truncated by server for size limits.]"
        content = content[: _MIRA_MAX_REPLY_CHARS - len(tail)] + tail

    handler_total_ms = round((time.perf_counter() - t_handler_start) * 1000, 3)
    mira_obs(
        "mira_chat_ok",
        request_id=request_id,
        ip=ip,
        authed=bool(user),
        messages=len(payload.messages),
        client_chars=client_chars,
        attachments=0,
        attach_bytes=0,
        attach_image=0,
        attach_pdf=0,
        attach_text=0,
        reply_chars=len(content),
        model=used_model,
        upstream_wall_ms=upstream_metrics.get("upstream_wall_ms"),
        first_token_ms=upstream_metrics.get("first_token_ms"),
        handler_total_ms=handler_total_ms,
    )
    return MiraChatResponse(message=content, model=used_model)
