"""MIRA assistant — proxies chat to a local or remote Ollama server."""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import logging
import os
from io import BytesIO
from typing import Any, Dict, List, Literal, Optional, Tuple

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from pypdf import PdfReader

from app.auth_rate_limit import client_ip, mira_rate_limit_or_429
from app.config import settings
from app.deps import AuthenticatedUser, optional_user
from app.mira_prompt import MIRA_SYSTEM_PROMPT
from app.storage import store

logger = logging.getLogger(__name__)

router = APIRouter(tags=["mira"])

# Roles the *client* may send. We inject the real system prompt server-side; client "system"
# turns are ignored so they cannot sit beside or override our system message in the model API.
_CLIENT_MESSAGE_ROLES = frozenset({"user", "assistant"})


def _sanitize_mira_text(text: str) -> str:
    """Remove NULs and C0 control chars (keep tab/newline/cr). Does not stop prompt injection."""
    if not text:
        return ""
    t = text.replace("\x00", "").replace("\ufeff", "")
    return "".join(
        ch for ch in t if ch in "\t\n\r" or (ord(ch) >= 32 and ord(ch) != 127)
    )


class MiraChatMessage(BaseModel):
    model_config = ConfigDict(extra="ignore")

    role: Literal["user", "assistant", "system"]
    content: str = Field(..., min_length=1, max_length=12000)


class MiraChatAttachment(BaseModel):
    """One file from the client: UTF-8 text, base64 image, or base64 PDF."""

    model_config = ConfigDict(extra="ignore")

    filename: str = Field(default="file", max_length=240)
    mime_type: str = Field(default="application/octet-stream", max_length=120)
    encoding: Literal["utf8", "base64"] = "utf8"
    data: str = Field(..., max_length=6_000_000)


class MiraChatBody(BaseModel):
    model_config = ConfigDict(extra="ignore")

    messages: List[MiraChatMessage] = Field(..., min_length=1, max_length=48)
    attachments: Optional[List[MiraChatAttachment]] = Field(default=None, max_length=10)


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


_MIRA_MAX_IMAGES = 4
_MIRA_MAX_PDF_DECODED_BYTES = 4 * 1024 * 1024
_MIRA_IMAGE_B64_MAX_CHARS = 5_500_000
_MIRA_MERGED_ATTACH_TEXT_MAX = 100_000
_MIRA_PER_TEXT_FILE_MAX = 120_000

_TEXT_MIMES = frozenset(
    {
        "text/plain",
        "text/markdown",
        "text/csv",
        "text/xml",
        "application/json",
        "application/xml",
        "application/yaml",
        "text/yaml",
        "application/x-yaml",
    }
)


def _strip_data_url_b64(data: str) -> str:
    s = (data or "").strip()
    if s.startswith("data:") and "," in s:
        return s.split(",", 1)[1].strip()
    return s


def _mime_is_image(mime: str) -> bool:
    return (mime or "").strip().lower().startswith("image/")


def _mime_is_pdf(mime: str, filename: str) -> bool:
    m = (mime or "").strip().lower()
    if m == "application/pdf":
        return True
    return (filename or "").lower().endswith(".pdf")


def _mime_textish(mime: str, filename: str) -> bool:
    m = (mime or "").strip().lower()
    if m in _TEXT_MIMES or m.startswith("text/"):
        return True
    fn = (filename or "").lower()
    return fn.endswith(
        (".txt", ".md", ".markdown", ".csv", ".json", ".xml", ".yaml", ".yml", ".log", ".env")
    )


def _extract_pdf_text(raw: bytes, max_chars: int = 120_000) -> str:
    try:
        reader = PdfReader(BytesIO(raw))
    except Exception:
        return ""
    parts: List[str] = []
    for i, page in enumerate(reader.pages):
        if i >= 100:
            break
        try:
            t = page.extract_text() or ""
        except Exception:
            t = ""
        if t and t.strip():
            parts.append(t.strip())
    out = "\n\n".join(parts).strip()
    return out[:max_chars]


def merge_mira_attachments(attachments: List[MiraChatAttachment]) -> Tuple[str, List[str], int]:
    """Build extra user text plus up to four base64 images for Ollama."""
    extra_parts: List[str] = []
    images: List[str] = []
    raw_byte_budget = 0

    for i, item in enumerate(attachments):
        fname = _sanitize_mira_text(item.filename).strip() or f"file_{i + 1}"
        mime = (item.mime_type or "").strip().lower()
        enc = item.encoding

        if _mime_is_image(mime):
            if enc != "base64":
                raise HTTPException(
                    status_code=400,
                    detail=f"Image attachment {fname} must use encoding base64.",
                )
            b64 = _strip_data_url_b64(item.data)
            if not b64:
                raise HTTPException(status_code=400, detail=f"Image {fname} is empty.")
            if len(b64) > _MIRA_IMAGE_B64_MAX_CHARS:
                raise HTTPException(status_code=400, detail=f"Image {fname} is too large.")
            try:
                decoded = base64.b64decode(b64, validate=True)
            except binascii.Error as exc:
                raise HTTPException(
                    status_code=400,
                    detail=f"Image {fname}: invalid base64.",
                ) from exc
            if len(decoded) > 4 * 1024 * 1024:
                raise HTTPException(
                    status_code=400,
                    detail=f"Image {fname} exceeds 4MB after decoding.",
                )
            raw_byte_budget += len(decoded)
            if len(images) >= _MIRA_MAX_IMAGES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Too many images (max {_MIRA_MAX_IMAGES} per message).",
                )
            images.append(b64)
            continue

        if _mime_is_pdf(mime, fname):
            if enc != "base64":
                raise HTTPException(
                    status_code=400,
                    detail=f"PDF {fname} must use encoding base64.",
                )
            b64 = _strip_data_url_b64(item.data)
            try:
                decoded = base64.b64decode(b64, validate=False)
            except (binascii.Error, ValueError) as exc:
                raise HTTPException(
                    status_code=400,
                    detail=f"PDF {fname}: invalid base64.",
                ) from exc
            if len(decoded) > _MIRA_MAX_PDF_DECODED_BYTES:
                raise HTTPException(status_code=400, detail=f"PDF {fname} exceeds 4MB.")
            raw_byte_budget += len(decoded)
            extracted = _extract_pdf_text(decoded)
            snippet = _sanitize_mira_text(extracted) if extracted else ""
            if not snippet.strip():
                extra_parts.append(f"--- Attached PDF: {fname} (no extractable text) ---")
            else:
                cap_file = min(len(snippet), _MIRA_PER_TEXT_FILE_MAX)
                extra_parts.append(f"--- Attached PDF: {fname} ---\n{snippet[:cap_file]}")
            continue

        if _mime_textish(mime, fname):
            if enc == "base64":
                b64 = _strip_data_url_b64(item.data)
                try:
                    decoded = base64.b64decode(b64, validate=False)
                except (binascii.Error, ValueError) as exc:
                    raise HTTPException(
                        status_code=400,
                        detail=f"File {fname}: invalid base64.",
                    ) from exc
                text = decoded.decode("utf-8", errors="replace")
            else:
                text = item.data
            text = _sanitize_mira_text(text)
            if not text.strip():
                extra_parts.append(f"--- Attached file: {fname} (empty) ---")
            else:
                cap_file = min(len(text), _MIRA_PER_TEXT_FILE_MAX)
                extra_parts.append(f"--- Attached file: {fname} ---\n{text[:cap_file]}")
            raw_byte_budget += cap_file
            continue

        raise HTTPException(
            status_code=400,
            detail=(
                f"Unsupported attachment ({mime or 'unknown type'}) for {fname}. "
                "Use an image, PDF, or text-based file (txt, md, json, csv, yaml, xml, log)."
            ),
        )

    merged = "\n\n".join(extra_parts).strip()
    if len(merged) > _MIRA_MERGED_ATTACH_TEXT_MAX:
        merged = merged[:_MIRA_MERGED_ATTACH_TEXT_MAX] + "\n[…attachment text truncated…]"
    return merged, images, raw_byte_budget


def _last_user_message_index(messages: List[MiraChatMessage]) -> Optional[int]:
    for i in range(len(messages) - 1, -1, -1):
        if messages[i].role == "user":
            return i
    return None


def _last_user_text(messages: List[MiraChatMessage]) -> str:
    for m in reversed(messages):
        if m.role == "user":
            return _sanitize_mira_text(m.content).strip()
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

    Optional `attachments` (max 10) are merged into the latest user turn: UTF-8 text and extracted
    PDF text become prompt context; images are passed as base64 to Ollama when the model supports vision.
    """
    _require_mira_enabled()
    ip = client_ip(request)
    mira_rate_limit_or_429(
        ip,
        settings.mira_rate_max_requests,
        settings.mira_rate_window_sec,
    )
    attach_list = list(payload.attachments or [])
    extra_text, image_b64s, attach_byte_metric = (
        merge_mira_attachments(attach_list) if attach_list else ("", [], 0)
    )

    client_chars = sum(len(m.content) for m in payload.messages)
    client_chars += len(extra_text) + sum(len(b) for b in image_b64s)
    logger.info(
        "mira_chat start ip=%s authed=%s messages=%d client_chars=%d attachments=%d attach_bytes~=%d",
        ip,
        bool(user),
        len(payload.messages),
        client_chars,
        len(attach_list),
        attach_byte_metric,
    )

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

    last_u = _last_user_message_index(payload.messages)
    ollama_messages: List[Dict[str, Any]] = [{"role": "system", "content": _system_prompt_for_user(user)}]
    for i, m in enumerate(payload.messages):
        if m.role not in _CLIENT_MESSAGE_ROLES:
            continue
        piece = _sanitize_mira_text(m.content)
        last_user_turn = last_u is not None and i == last_u and m.role == "user"
        if not piece:
            if last_user_turn and (extra_text.strip() or image_b64s):
                piece = (
                    "Please analyze the attached file(s). "
                    "Focus on anything security-relevant or actionable."
                )
            else:
                continue
        entry: Dict[str, Any] = {"role": m.role, "content": piece}
        if last_user_turn and (extra_text.strip() or image_b64s):
            if extra_text.strip():
                merged = f"{extra_text}\n\n--- User message ---\n{piece}"
            else:
                merged = piece
            if len(merged) > 200_000:
                merged = merged[:200_000] + "\n[…truncated…]"
            entry["content"] = merged
            if image_b64s:
                entry["images"] = image_b64s
        ollama_messages.append(entry)

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
    try:
        async with httpx.AsyncClient(timeout=stream_timeout) as client:
            content, used_model = await _ollama_chat_stream_aggregate(
                client, url, body, ollama_headers, model, wall_seconds=wall
            )
    except httpx.ConnectError as exc:
        logger.warning(
            "mira_chat ollama_connect_fail ip=%s messages=%d client_chars=%d err=%s",
            ip,
            len(payload.messages),
            client_chars,
            exc,
        )
        raise HTTPException(
            status_code=503,
            detail="Could not reach the language model server. Check OLLAMA_BASE_URL and network access.",
        ) from exc
    except httpx.TimeoutException as exc:
        logger.warning(
            "mira_chat ollama_http_timeout ip=%s messages=%d client_chars=%d detail=%s",
            ip,
            len(payload.messages),
            client_chars,
            str(exc)[:200],
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
        logger.warning(
            "mira_chat empty_reply ip=%s messages=%d client_chars=%d",
            ip,
            len(payload.messages),
            client_chars,
        )
        raise HTTPException(status_code=502, detail="Empty reply from model.")

    if user:
        u_text = _last_user_text(payload.messages)
        if u_text:
            try:
                store.ensure_user(user.sub, user.email)
                store.append_mira_user_memory(user.sub, u_text, content)
            except Exception:
                logger.exception("MIRA user memory update failed for sub=%s", user.sub)

    logger.info(
        "mira_chat ok ip=%s authed=%s messages=%d client_chars=%d reply_chars=%d model=%s",
        ip,
        bool(user),
        len(payload.messages),
        client_chars,
        len(content),
        used_model,
    )
    return MiraChatResponse(message=content, model=used_model)
