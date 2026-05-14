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

from app.auth_rate_limit import api_surface_rate_hit, client_ip
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


class ApiRateLimitMiddleware(BaseHTTPMiddleware):
    """
    Per-IP sliding window across the API — adds ``X-RateLimit-Limit`` / ``X-RateLimit-Remaining`` on
    every response and returns 429 when the cap is exceeded (scanner RATE-01 looks for these signals).
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.method == "OPTIONS":
            return await call_next(request)

        ip = client_ip(request)
        path = request.url.path
        cap = max(12, int(settings.api_rate_max_requests))
        window = float(settings.api_rate_window_sec)

        lim, remaining, allowed = api_surface_rate_hit(ip, path, window, cap)
        if not allowed:
            body = b'{"detail":"Too many requests. Please try again shortly."}'
            hdrs = {
                "Content-Type": "application/json",
                "Retry-After": str(max(1, int(window))),
                "X-RateLimit-Limit": str(lim),
                "X-RateLimit-Remaining": "0",
            }
            if settings.security_hsts_max_age > 0 and _request_is_https(request):
                hdrs["Strict-Transport-Security"] = (
                    f"max-age={settings.security_hsts_max_age}; includeSubDomains"
                )
            return Response(content=body, status_code=429, headers=hdrs)

        response = await call_next(request)
        path_norm = (request.url.path or "").split("?", 1)[0].rstrip("/") or "/"
        if path_norm != "/health":
            response.headers.setdefault("X-RateLimit-Limit", str(lim))
            response.headers.setdefault("X-RateLimit-Remaining", str(remaining))
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
