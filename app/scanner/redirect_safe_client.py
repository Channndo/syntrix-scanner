"""
Manual redirect following for outbound scan probes.

``httpx`` with ``follow_redirects=True`` only validates the *first* URL — a server can 302 to
cloud metadata, loopback, or another forbidden host. We cap hops and re-apply the same
``is_allowed`` predicate on every absolute URL before issuing the next request.

Cross-host redirects drop ``Authorization`` / ``Cookie`` / ``Proxy-Authorization`` (and httpx
``auth`` / ``cookies`` kwargs) so a malicious target cannot harvest credentials from the scanner.

Only ``http`` and ``https`` URLs are ever passed to the inner client — ``file:``, ``gopher:``,
``dict:``, etc. are rejected even if ``is_allowed`` is misconfigured.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional
from urllib.parse import urljoin, urlparse

import httpx

from app.scanner.probe_url_policy import is_probe_scheme_allowed, is_probe_url_shape_acceptable

# Enough for typical http→https and trailing-slash chains; stops redirect loops cheaply.
_MAX_SCAN_REDIRECTS = 8

# Header names compared case-insensitively — anything that commonly carries secrets across origins.
_STRIP_ON_CROSS_HOST = frozenset({
    "authorization",
    "cookie",
    "cookie2",
    "proxy-authorization",
})


def _host_key(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _strip_cross_host_secrets(kw: Dict[str, Any]) -> None:
    """Remove credential-bearing fields before following a redirect to another host."""
    kw.pop("auth", None)
    kw.pop("cookies", None)
    raw = kw.get("headers")
    if not raw:
        return
    h = httpx.Headers(raw)
    for name in list(h.keys()):
        if name.lower() in _STRIP_ON_CROSS_HOST:
            del h[name]
    kw["headers"] = h


class RedirectSafeAsyncClient:
    """
    Duck-types like ``httpx.AsyncClient`` for ``.get`` / ``.post`` / ``.request`` used by checks.

    Wraps a real client that must be constructed with ``follow_redirects=False``.
    """

    def __init__(self, inner: httpx.AsyncClient, is_allowed: Callable[[str], bool]) -> None:
        self._inner = inner
        self._is_allowed = is_allowed

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._follow("GET", url, dict(kwargs))

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._follow("POST", url, dict(kwargs))

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        return await self._follow(str(method).upper(), url, dict(kwargs))

    async def _follow(self, method: str, url: str, kw: Dict[str, Any]) -> httpx.Response:
        kw.pop("follow_redirects", None)
        current = str(url).strip()
        m = method.upper()
        last: Optional[httpx.Response] = None

        for _ in range(_MAX_SCAN_REDIRECTS + 1):
            if not is_probe_url_shape_acceptable(current):
                if last is not None:
                    return last
                raise httpx.InvalidURL(
                    "Scan probe URL rejected (length, line breaks, or embedded userinfo in URL; "
                    "see SYNTRIX_PROBE_MAX_TARGET_URL_CHARS)."
                )

            if not is_probe_scheme_allowed(current):
                if last is not None:
                    return last
                raise httpx.UnsupportedProtocol(
                    "Syntrix scanner probes only http:// and https:// URLs "
                    f"(got scheme {urlparse(current).scheme!r})."
                )

            if not self._is_allowed(current):
                if last is not None:
                    return last
                return await self._inner.request(m, current, follow_redirects=False, **kw)

            r = await self._inner.request(m, current, follow_redirects=False, **kw)
            last = r

            if r.status_code not in (301, 302, 303, 307, 308):
                return r

            loc = (r.headers.get("location") or "").strip()
            if not loc:
                return r

            next_url = urljoin(current, loc)
            if not self._is_allowed(next_url):
                return r

            # 303 always switches to GET (RFC); drop body-like kwargs so the next hop is safe.
            if r.status_code == 303 and m != "HEAD":
                m = "GET"
                for drop in ("content", "data", "json", "files"):
                    kw.pop(drop, None)

            if _host_key(current) != _host_key(next_url):
                _strip_cross_host_secrets(kw)

            current = next_url

        return last if last is not None else r
