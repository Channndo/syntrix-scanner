"""Simple per-IP rate limiting for login/register endpoints."""

from __future__ import annotations

import threading
import time
from typing import Dict, List

from fastapi import HTTPException, Request, status

_RATE_LOCK = threading.Lock()
_RATE_HITS: Dict[str, List[float]] = {}
_RATE_WINDOW_SEC = 60.0
_RATE_MAX_REQUESTS = 25


def client_ip(request: Request) -> str:
    ff = (request.headers.get("x-forwarded-for") or "").strip()
    if ff:
        return ff.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def rate_limit_or_429(ip: str) -> None:
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
