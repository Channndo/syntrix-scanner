"""Shared rules for what URLs outbound scan probes may touch."""

from __future__ import annotations

from urllib.parse import urlparse

from app.config import settings

_ALLOWED_PROBE_SCHEMES = frozenset({"http", "https"})


def is_probe_scheme_allowed(url: str) -> bool:
    """
    Only ``http`` and ``https`` — reject ``file:``, ``gopher:``, ``dict:``, ``ftp:``, etc.

    Used by ``_is_target_allowed`` and ``RedirectSafeAsyncClient`` so unsafe schemes never reach
    httpx, even when a custom ``is_allowed`` predicate is permissive.
    """
    scheme = (urlparse(str(url).strip()).scheme or "").lower()
    return scheme in _ALLOWED_PROBE_SCHEMES


def is_probe_url_shape_acceptable(url: str) -> bool:
    """
    Reject absurdly long targets, CRLF smuggling in strings, and ``userinfo`` in the authority.

    Public scanners should not accept ``https://secret:token@host/`` (credential leak + SSRF
    foot-gun) or multi-megabyte URL strings. Tuned via ``SYNTRIX_PROBE_MAX_TARGET_URL_CHARS``.
    """
    raw = str(url)
    if "\n" in raw or "\r" in raw:
        return False
    t = raw.strip()
    if not t or len(t) > settings.probe_max_target_url_chars:
        return False
    p = urlparse(t)
    if p.username is not None or p.password is not None:
        return False
    return True
