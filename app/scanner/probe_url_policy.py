"""Shared rules for what URLs outbound scan probes may touch."""

from __future__ import annotations

from urllib.parse import urlparse

_ALLOWED_PROBE_SCHEMES = frozenset({"http", "https"})


def is_probe_scheme_allowed(url: str) -> bool:
    """
    Only ``http`` and ``https`` — reject ``file:``, ``gopher:``, ``dict:``, ``ftp:``, etc.

    Used by ``_is_target_allowed`` and ``RedirectSafeAsyncClient`` so unsafe schemes never reach
    httpx, even when a custom ``is_allowed`` predicate is permissive.
    """
    scheme = (urlparse(str(url).strip()).scheme or "").lower()
    return scheme in _ALLOWED_PROBE_SCHEMES
