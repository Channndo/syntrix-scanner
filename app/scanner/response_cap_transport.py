"""
Wrap the default async HTTP transport to cap how many bytes we read from any probe response.

Malicious or buggy targets can return multi‑gigabyte bodies or drip bytes slowly; without a cap the
scanner worker holds growing buffers and becomes easy to DoS from the public scan surface.
"""

from __future__ import annotations

import typing

import httpx
from httpx import AsyncBaseTransport, Request, Response
from httpx._types import AsyncByteStream

if typing.TYPE_CHECKING:
    from types import TracebackType


class _CappedAsyncStream(AsyncByteStream):
    def __init__(self, inner: AsyncByteStream, max_bytes: int) -> None:
        self._inner = inner
        self._max = max_bytes
        self._total = 0

    async def __aiter__(self) -> typing.AsyncIterator[bytes]:
        async for chunk in self._inner:
            self._total += len(chunk)
            if self._total > self._max:
                await self.aclose()
                raise httpx.RemoteProtocolError(
                    f"Response body exceeds SYNTRIX_PROBE_MAX_RESPONSE_BYTES ({self._max})."
                )
            yield chunk

    async def aclose(self) -> None:
        await self._inner.aclose()


class ResponseCapTransport(httpx.AsyncBaseTransport):
    """
    Async transport that delegates to another ``AsyncBaseTransport`` (typically ``AsyncHTTPTransport``)
    and wraps the response byte stream.

    Also rejects responses whose ``Content-Length`` (when present as a single decimal value)
    exceeds the cap before streaming, so obvious oversize bodies fail fast.
    """

    def __init__(self, inner: AsyncBaseTransport, max_bytes: int) -> None:
        self._inner = inner
        self._max = max_bytes

    async def handle_async_request(self, request: Request) -> Response:
        resp = await self._inner.handle_async_request(request)
        cl = resp.headers.get("content-length")
        if cl is not None:
            raw = cl.strip().split(",", 1)[0].strip()
            try:
                n = int(raw)
            except ValueError:
                n = -1
            if n > self._max:
                await resp.aclose()
                raise httpx.RemoteProtocolError(
                    f"Content-Length {n} exceeds SYNTRIX_PROBE_MAX_RESPONSE_BYTES ({self._max})."
                )
        return Response(
            status_code=resp.status_code,
            headers=resp.headers,
            stream=_CappedAsyncStream(resp.stream, self._max),
            extensions=resp.extensions,
        )

    async def __aenter__(self) -> "ResponseCapTransport":
        await self._inner.__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: typing.Optional[typing.Type[BaseException]] = None,
        exc_value: typing.Optional[BaseException] = None,
        traceback: typing.Optional["TracebackType"] = None,
    ) -> None:
        await self._inner.__aexit__(exc_type, exc_value, traceback)

    async def aclose(self) -> None:
        await self._inner.aclose()
