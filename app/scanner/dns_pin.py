"""
DNS pinning for outbound scan probes.

``httpx`` resolves the hostname again at connect time. A malicious or racing resolver can answer
“safe” at policy time and “internal” at TCP time (DNS rebinding / TOCTOU). We resolve once, filter
addresses with the same policy as literals, then open TCP to that exact address while keeping
``Host`` / TLS SNI on the original name.

Multi-IP workflows (e.g. scanning each A/AAAA for a hostname) can call ``build_pinned_request_parts``
with different ``pin_ip`` values; each hop still avoids a second DNS lookup for that choice.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import ParseResult, urlunparse, urlparse

import httpx

from app.config import settings


def resolved_ip_allowed(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Same policy as literal IPs: link-local and multicast never; private/loopback env-gated."""
    if addr.is_link_local:
        return False
    if addr.is_loopback:
        return bool(settings.allow_localhost_scans)
    if addr.is_private or addr.is_reserved or addr.is_unspecified:
        return bool(settings.allow_private_network_scans)
    if addr.is_multicast:
        return False
    return True


def _default_port_for_scheme(scheme: str) -> int:
    s = (scheme or "http").lower()
    return 443 if s in ("https", "wss") else 80


def _netloc_ip_and_maybe_port(pin_ip: str, port: Optional[int], scheme: str) -> str:
    raw = (pin_ip or "").strip()
    addr = ipaddress.ip_address(raw.split("%", 1)[0])
    if addr.version == 6:
        hostpart = f"[{addr.compressed}]"
    else:
        hostpart = addr.compressed
    default_p = _default_port_for_scheme(scheme)
    if port is not None and int(port) != default_p:
        return f"{hostpart}:{int(port)}"
    return hostpart


def build_host_header_value(parsed: ParseResult) -> str:
    """RFC 7230 Host header for the original URL (name + non-default port)."""
    hp = parsed.hostname or ""
    if not hp:
        return ""
    default_p = _default_port_for_scheme(parsed.scheme or "http")
    if parsed.port is not None and int(parsed.port) != default_p:
        return f"{hp}:{int(parsed.port)}"
    return hp


def build_pinned_request_parts(url: str, pin_ip: str) -> Tuple[str, Dict[str, str], Dict[str, Any]]:
    """
    Rewrite ``url`` so TCP connects to ``pin_ip`` while preserving path/query/fragment.

    Returns ``(new_url, header_overrides, extensions)``. For IP-literal hosts, returns the
    original URL and empty dicts.
    """
    p = urlparse(url.strip())
    h = p.hostname
    if not h:
        return url, {}, {}
    try:
        ipaddress.ip_address(h)
        return url, {}, {}
    except ValueError:
        pass

    new_netloc = _netloc_ip_and_maybe_port(pin_ip, p.port, p.scheme or "http")
    if p.username or p.password:
        auth = (p.username or "") + (f":{p.password}" if p.password else "")
        new_netloc = f"{auth}@{new_netloc}"

    new_p = ParseResult(
        scheme=p.scheme,
        netloc=new_netloc,
        path=p.path or "",
        params=p.params,
        query=p.query,
        fragment=p.fragment,
    )
    new_url = urlunparse(new_p)
    hdr = {"Host": build_host_header_value(p)}
    ext: Dict[str, Any] = {}
    if (p.scheme or "").lower() in ("https", "wss"):
        ext["sni_hostname"] = h
    return new_url, hdr, ext


async def resolve_scan_host(hostname: str) -> List[str]:
    """
    Return ordered unique addresses from ``getaddrinfo`` that pass ``resolved_ip_allowed``.

    Zone IDs (``fe80::1%eth0``) are stripped for pinning.
    """
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(
            hostname,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror:
        return []

    seen: set[str] = set()
    out: List[str] = []
    for _fam, _typ, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if isinstance(ip, bytes):  # pragma: no cover - rare on modern Python
            continue
        if "%" in ip:
            ip = ip.split("%", 1)[0]
        try:
            parsed_ip = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if not resolved_ip_allowed(parsed_ip):
            continue
        if ip in seen:
            continue
        seen.add(ip)
        out.append(ip)
    return out


class DnsPinnedAsyncClient:
    """
    Duck-types like ``httpx.AsyncClient`` for ``.get`` / ``.post`` / ``.request``.

    Caches one chosen pin address per hostname for the lifetime of this wrapper (one scan). The
    first resolution wins for that host so concurrent probes do not race different addresses; use
    ``build_pinned_request_parts`` with explicit ``pin_ip`` from ``resolve_scan_host`` when you need
    every address probed individually.
    """

    def __init__(
        self,
        inner: httpx.AsyncClient,
        *,
        initial_host_pins: Optional[Dict[str, str]] = None,
    ) -> None:
        self._inner = inner
        self._pin_by_host: Dict[str, str] = {
            k.lower(): v for k, v in (initial_host_pins or {}).items()
        }
        self._lock = asyncio.Lock()

    async def _pin_for_host(self, host: str) -> Optional[str]:
        key = host.lower()
        if key in self._pin_by_host:
            return self._pin_by_host[key]
        async with self._lock:
            if key in self._pin_by_host:
                return self._pin_by_host[key]
            addrs = await resolve_scan_host(host)
            if not addrs:
                return None
            self._pin_by_host[key] = addrs[0]
            return addrs[0]

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        kw = dict(kwargs)
        merged = httpx.Headers(kw.pop("headers", None))
        extensions = dict(kw.pop("extensions", None) or {})

        p = urlparse(str(url).strip())
        h = p.hostname
        if not h:
            return await self._inner.request(method, str(url).strip(), headers=merged, extensions=extensions, **kw)

        try:
            ipaddress.ip_address(h)
            return await self._inner.request(method, str(url).strip(), headers=merged, extensions=extensions, **kw)
        except ValueError:
            pass

        pin = await self._pin_for_host(h)
        if pin is None:
            raise httpx.ConnectError(f"No permitted address resolved for host {h!r}")

        new_url, hdr_patch, ext_patch = build_pinned_request_parts(str(url).strip(), pin)
        for hk, hv in hdr_patch.items():
            merged[hk] = hv
        merged_extensions = {**ext_patch, **extensions}
        return await self._inner.request(
            method,
            new_url,
            headers=merged,
            extensions=merged_extensions,
            **kw,
        )
