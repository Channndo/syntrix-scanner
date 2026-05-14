"""Redirect-safe scan client — each hop must pass the same host policy as the initial URL."""

import asyncio

import httpx

from app.scanner.engine import _is_target_allowed
from app.scanner.redirect_safe_client import RedirectSafeAsyncClient


def _run(coro):
    return asyncio.run(coro)


async def _redirect_to_metadata_not_followed():
    def handler(request: httpx.Request) -> httpx.Response:
        u = str(request.url).rstrip("/")
        if u == "https://example.com/start":
            return httpx.Response(
                302,
                headers={"Location": "http://169.254.169.254/latest/meta-data/"},
            )
        raise AssertionError(f"scanner must not request disallowed redirect target: {request.url}")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, follow_redirects=False) as inner:
        c = RedirectSafeAsyncClient(inner, _is_target_allowed)
        r = await c.get("https://example.com/start")
    assert r.status_code == 302


def test_redirect_to_metadata_not_followed():
    _run(_redirect_to_metadata_not_followed())


async def _redirect_chain_same_host_ok():
    def handler(request: httpx.Request) -> httpx.Response:
        u = str(request.url).rstrip("/")
        if u == "https://example.com/start":
            return httpx.Response(302, headers={"Location": "https://example.com/final"})
        if u == "https://example.com/final":
            return httpx.Response(200, text="done")
        raise AssertionError(str(request.url))

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, follow_redirects=False) as inner:
        c = RedirectSafeAsyncClient(inner, _is_target_allowed)
        r = await c.get("https://example.com/start")
    assert r.status_code == 200
    assert r.text == "done"


def test_redirect_chain_same_host_ok():
    _run(_redirect_chain_same_host_ok())


async def _custom_policy_blocks_cross_host():
    def allows(url: str) -> bool:
        return str(url).startswith("https://good.com")

    def handler(request: httpx.Request) -> httpx.Response:
        u = str(request.url).rstrip("/")
        if u == "https://good.com/a":
            return httpx.Response(302, headers={"Location": "https://evil.com/b"})
        raise AssertionError(str(request.url))

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, follow_redirects=False) as inner:
        c = RedirectSafeAsyncClient(inner, allows)
        r = await c.get("https://good.com/a")
    assert r.status_code == 302


def test_custom_policy_blocks_cross_host():
    _run(_custom_policy_blocks_cross_host())


async def _post_303_drops_json_body():
    def handler(request: httpx.Request) -> httpx.Response:
        u = str(request.url).rstrip("/")
        if u == "https://example.com/api":
            return httpx.Response(303, headers={"Location": "https://example.com/see"})
        if u == "https://example.com/see":
            assert request.method == "GET"
            return httpx.Response(200, text="ok")
        raise AssertionError(str(request.url))

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, follow_redirects=False) as inner:
        c = RedirectSafeAsyncClient(inner, _is_target_allowed)
        r = await c.post("https://example.com/api", json={"x": 1})
    assert r.status_code == 200


def test_post_303_drops_json_body():
    _run(_post_303_drops_json_body())
