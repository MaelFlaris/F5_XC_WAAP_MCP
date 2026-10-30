"""Hardened HTTP client for the F5 XC API.

* base URL derived only from the validated tenant;
* TLS verification always on (an extra CA bundle can be added, never disabled);
* redirects are not followed, no automatic retries;
* responses are read in streaming mode and cut at ``max_response_bytes``;
* the caller's token is attached per request and never stored on the client.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
from pydantic import SecretStr

from .config import Settings
from .errors import Code, SecureError

USER_AGENT = "f5xc-waap-mcp/0.1"

_STATUS = {
    400: Code.INVALID_ARGUMENT,
    401: Code.UPSTREAM_FORBIDDEN,
    403: Code.UPSTREAM_FORBIDDEN,
    404: Code.NOT_FOUND,
    409: Code.CONFLICT,
    429: Code.UPSTREAM_RATE_LIMITED,
}


class XCClient:
    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._settings = settings
        verify: Any = settings.ca_bundle or True
        self._http = httpx.AsyncClient(
            base_url=settings.base_url,
            verify=verify,
            follow_redirects=False,
            timeout=httpx.Timeout(settings.request_timeout_s, connect=min(10.0, settings.request_timeout_s)),
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            transport=transport or httpx.AsyncHTTPTransport(retries=0, verify=verify, proxy=settings.https_proxy),
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def request(
        self,
        method: str,
        path: str,
        token: SecretStr,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> Any:
        if not path.startswith("/api/"):
            raise SecureError(Code.INTERNAL, detail="path outside /api")
        headers = {"Authorization": f"APIToken {token.get_secret_value()}"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        cap = self._settings.max_response_bytes
        buffer = bytearray()
        try:
            async with self._http.stream(
                method, path, params=params, headers=headers,
                content=json.dumps(body).encode() if body is not None else None,
            ) as response:
                status = response.status_code
                if 300 <= status < 400:
                    raise SecureError(Code.UPSTREAM_REDIRECT, status=status)
                async for chunk in response.aiter_bytes():
                    buffer.extend(chunk)
                    if len(buffer) > cap:
                        raise SecureError(Code.RESPONSE_TOO_LARGE, status=status)
        except httpx.TimeoutException as exc:
            raise SecureError(Code.UPSTREAM_TIMEOUT, detail=type(exc).__name__) from exc
        except httpx.TransportError as exc:
            raise SecureError(Code.UPSTREAM_UNREACHABLE, detail=type(exc).__name__) from exc

        if status >= 400:
            code = _STATUS.get(status, Code.UPSTREAM_ERROR)
            # The upstream message is not echoed back: it may contain input
            # values. It only goes to the audit detail, scrubbed.
            raise SecureError(code, f"(HTTP {status})", detail=bytes(buffer[:300]).decode("utf-8", "replace"),
                              status=status)
        if not buffer:
            return {}
        try:
            return json.loads(bytes(buffer))
        except (ValueError, UnicodeDecodeError) as exc:
            raise SecureError(Code.RESPONSE_INVALID, status=status) from exc
