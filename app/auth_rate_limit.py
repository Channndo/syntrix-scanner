"""
Cheap per-IP throttles — in-memory, process-local.

Good enough for v1 on a single Render instance: stops brute-force on auth and stops someone from
hammering MIRA into your Ollama bill. If we ever horizontally scale, this becomes “per box” unless
we graduate to Redis — that’s a known tradeoff, not a surprise.
"""

from __future__ import annotations

import threading
import time
from typing import Dict, List

from fastapi import HTTPException, Request, status

from app.mira_obs import mira_obs

_RATE_LOCK = threading.Lock()
_RATE_HITS: Dict[str, List[float]] = {}
_RATE_WINDOW_SEC = 60.0
_RATE_MAX_REQUESTS = 25

_MIRA_RATE_LOCK = threading.Lock()
_MIRA_RATE_HITS: Dict[str, List[float]] = {}


def client_ip(request: Request) -> str:
    """Best-effort client IP: honor ``X-Forwarded-For`` (Render/proxies) then fall back to socket."""
    ff = (request.headers.get("x-forwarded-for") or "").strip()
    if ff:
        return ff.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def rate_limit_or_429(ip: str) -> None:
    """Login/register throttle — sliding 60s window, shared across those routes."""
    now = time.monotonic()
    with _RATE_LOCK:
        hits = _RATE_HITS.setdefault(ip, [])
        cutoff = now - _RATE_WINDOW_SEC
        while hits and hits[0] < cutoff:
            hits.pop(0)
        if len(hits) >= _RATE_MAX_REQUESTS:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many attempts. Try again shortly.",
            )
        hits.append(now)


def mira_rate_limit_or_429(ip: str, max_requests: int, window_sec: float) -> None:
    """
    MIRA-only bucket — separate from auth so a noisy chat user doesn’t lock themselves out of login.

    Emits ``mira_rate_limited`` via ``mira_obs`` right before the 429 so ops can graph abuse.
    """
    if max_requests <= 0 or window_sec <= 0:
        return
    now = time.monotonic()
    with _MIRA_RATE_LOCK:
        hits = _MIRA_RATE_HITS.setdefault(ip, [])
        cutoff = now - window_sec
        while hits and hits[0] < cutoff:
            hits.pop(0)
        if len(hits) >= max_requests:
            mira_obs(
                "mira_rate_limited",
                ip=ip,
                max_requests=max_requests,
                window_sec=round(window_sec, 3),
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many MIRA requests. Try again shortly.",
            )
        hits.append(now)
