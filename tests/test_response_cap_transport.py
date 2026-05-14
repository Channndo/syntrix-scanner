"""Outbound probe response size cap (SYNTRIX_PROBE_MAX_RESPONSE_BYTES)."""

import asyncio

import httpx
import pytest

from app.scanner.response_cap_transport import ResponseCapTransport


def _run(coro):
    return asyncio.run(coro)


async def _cl_too_large():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-length": "9000000"}, text="x")

    cap = ResponseCapTransport(httpx.MockTransport(handler), max_bytes=1000)
    async with httpx.AsyncClient(transport=cap, follow_redirects=False) as client:
        with pytest.raises(httpx.RemoteProtocolError, match="Content-Length"):
            await client.get("https://example.com/")


def test_rejects_content_length_over_cap():
    _run(_cl_too_large())


async def _body_stream_over_cap():
    class Chunks(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"a" * 30
            yield b"b" * 80

        async def aclose(self) -> None:
            pass

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=Chunks())

    cap = ResponseCapTransport(httpx.MockTransport(handler), max_bytes=100)
    async with httpx.AsyncClient(transport=cap, follow_redirects=False) as client:
        with pytest.raises(httpx.RemoteProtocolError, match="SYNTRIX_PROBE_MAX_RESPONSE_BYTES"):
            await client.get("https://example.com/")


def test_rejects_streaming_body_over_cap():
    _run(_body_stream_over_cap())
