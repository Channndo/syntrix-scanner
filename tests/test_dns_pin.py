"""DNS pinning — URL rewrite, policy filter, and httpx integration."""

import asyncio
import ipaddress

import httpx
import pytest

from app.config import settings
from app.scanner.dns_pin import (
    DnsPinnedAsyncClient,
    build_host_header_value,
    build_pinned_request_parts,
    resolved_ip_allowed,
    resolve_scan_host,
)
from app.scanner.engine import ScanEngine, ScanRequest


def _run(coro):
    return asyncio.run(coro)


def test_resolved_ip_allowed_public():
    assert resolved_ip_allowed(ipaddress.ip_address("8.8.8.8")) is True


def test_resolved_ip_private_blocked_by_default(monkeypatch):
    monkeypatch.setattr(settings, "allow_private_network_scans", False)
    assert resolved_ip_allowed(ipaddress.ip_address("10.0.0.1")) is False


def test_resolved_ip_private_when_flag(monkeypatch):
    monkeypatch.setattr(settings, "allow_private_network_scans", True)
    assert resolved_ip_allowed(ipaddress.ip_address("10.0.0.1")) is True


def test_resolved_link_local_never(monkeypatch):
    monkeypatch.setattr(settings, "allow_private_network_scans", True)
    assert resolved_ip_allowed(ipaddress.ip_address("169.254.1.1")) is False


def test_build_pinned_https_host_and_sni():
    u, hdr, ext = build_pinned_request_parts("https://example.com/foo", "93.184.216.34")
    assert "93.184.216.34" in u
    assert hdr["Host"] == "example.com"
    assert ext.get("sni_hostname") == "example.com"


def test_build_pinned_http_nondefault_port_no_sni():
    u, hdr, ext = build_pinned_request_parts("http://example.com:8080/x", "10.0.0.1")
    assert u.startswith("http://10.0.0.1:8080/")
    assert hdr["Host"] == "example.com:8080"
    assert ext == {}


def test_build_pinned_ipv6_netloc():
    u, hdr, ext = build_pinned_request_parts("https://example.com/", "2606:4700:4700::1111")
    assert "[" in u and "2606:4700:4700::1111" in u
    assert hdr["Host"] == "example.com"
    assert ext.get("sni_hostname") == "example.com"


def test_build_pinned_literal_passthrough():
    u, hdr, ext = build_pinned_request_parts("https://8.8.8.8/", "1.1.1.1")
    assert u == "https://8.8.8.8/"
    assert hdr == {}
    assert ext == {}


def test_build_host_header_value_explicit_port():
    from urllib.parse import urlparse

    p = urlparse("https://example.com:8443/x")
    assert build_host_header_value(p) == "example.com:8443"


async def _resolve_dedupes(monkeypatch):
    async def fake_getaddrinfo(*_a, **_k):
        return [
            (2, 1, 6, "", ("8.8.8.8", 0)),
            (2, 1, 6, "", ("8.8.4.4", 0)),
            (2, 1, 6, "", ("8.8.8.8", 0)),
        ]

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
    out = await resolve_scan_host("ignored.example")
    assert out == ["8.8.8.8", "8.8.4.4"]


def test_resolve_scan_host_dedupes(monkeypatch):
    _run(_resolve_dedupes(monkeypatch))


async def _resolve_filters_private(monkeypatch):
    async def fake_getaddrinfo(*_a, **_k):
        return [(2, 1, 6, "", ("10.0.0.1", 0)), (2, 1, 6, "", ("8.8.8.8", 0))]

    monkeypatch.setattr(settings, "allow_private_network_scans", False)
    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
    out = await resolve_scan_host("x.test")
    assert out == ["8.8.8.8"]


def test_resolve_scan_host_drops_private(monkeypatch):
    _run(_resolve_filters_private(monkeypatch))


async def _dns_pinned_rewrites():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["host"] = request.headers.get("host")
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, follow_redirects=False) as inner:
        c = DnsPinnedAsyncClient(inner, initial_host_pins={"example.com": "93.184.216.34"})
        r = await c.get("https://example.com/path")
    assert r.status_code == 200
    assert "93.184.216.34" in captured["url"]
    assert captured["host"] == "example.com"


def test_dns_pinned_client_rewrites_to_bootstrap_ip():
    _run(_dns_pinned_rewrites())


async def _engine_dns_blocked(monkeypatch):
    async def empty_resolve(_host: str):
        return []

    monkeypatch.setattr("app.scanner.engine.resolve_scan_host", empty_resolve)
    eng = ScanEngine()
    res = await eng.run(
        ScanRequest(
            scan_id="t1",
            target="https://example.com/",
            scan_type="mcp",
            depth="quick",
        )
    )
    ids = [f["check_id"] for f in res.findings]
    assert "TARGET_DNS_BLOCKED" in ids


def test_engine_returns_dns_blocked_when_no_permitted_addrs(monkeypatch):
    _run(_engine_dns_blocked(monkeypatch))
