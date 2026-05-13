"""Cross-cutting HTTP hardening — headers and coarse body limits.

These sit outside individual routes so every response picks up baseline headers and huge POSTs
to known-heavy endpoints fail fast before JSON parsing burns RAM.
"""

from __future__ import annotations

import logging
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.config import settings

logger = logging.getLogger(__name__)


def _request_is_https(request: Request) -> bool:
    if request.url.scheme == "https":
        return True
    xf = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
    return xf == "https"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Baseline headers for an API — reduces drive-by MIME sniffing / clickjacking / referrer leaks."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Permissions-Policy",
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), "
            "microphone=(), payment=(), usb=()",
        )
        if settings.security_hsts_max_age > 0 and _request_is_https(request):
            response.headers.setdefault(
                "Strict-Transport-Security",
                f"max-age={settings.security_hsts_max_age}; includeSubDomains",
            )
        # MIRA replies can be sensitive; do not let shared caches retain POST responses.
        if request.method == "POST" and request.url.path.rstrip("/") == "/api/mira/chat":
            response.headers.setdefault("Cache-Control", "no-store")
        return response


class MiraBodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject oversized MIRA chat bodies using Content-Length before the app parses JSON."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.method != "POST":
            return await call_next(request)
        path = request.url.path
        if path.rstrip("/") != "/api/mira/chat":
            return await call_next(request)
        cl = (request.headers.get("content-length") or "").strip()
        if not cl.isdigit():
            return await call_next(request)
        n = int(cl)
        cap = max(256_000, int(settings.mira_max_request_body_bytes))
        if n > cap:
            logger.warning("mira_body_rejected content_length=%s cap=%s", n, cap)
            return Response(
                content='{"detail":"Request body too large for MIRA chat."}',
                status_code=413,
                media_type="application/json",
            )
        return await call_next(request)
