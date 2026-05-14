"""
Manual redirect following for outbound scan probes.

``httpx`` with ``follow_redirects=True`` only validates the *first* URL — a server can 302 to
cloud metadata, loopback, or another forbidden host. We cap hops and re-apply the same
``is_allowed`` predicate on every absolute URL before issuing the next request.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional
from urllib.parse import urljoin

import httpx

# Enough for typical http→https and trailing-slash chains; stops redirect loops cheaply.
_MAX_SCAN_REDIRECTS = 8


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

            current = next_url

        return last if last is not None else r
