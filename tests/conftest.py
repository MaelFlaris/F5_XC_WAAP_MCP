"""Test harness: a simulated F5 XC API (httpx.MockTransport) and an in-memory
MCP client connected to the real server, so every test goes through the full
chain (schema validation, identity, guardrails, audit, sanitisation)."""

from __future__ import annotations

import io
import json
from collections.abc import Callable
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from f5xc_waap_mcp.audit import AuditLog
from f5xc_waap_mcp.config import Settings
from f5xc_waap_mcp.runtime import Runtime
from f5xc_waap_mcp.server import build_server
from f5xc_waap_mcp.xc_client import XCClient

TOKEN = "TestPersonalApiToken-0123456789abcdef"
WHOAMI = "/api/web/custom/namespaces/system/whoami"
USERS = {
    TOKEN: {"name": "alice@example.com", "email": "alice@example.com", "user_uuid": "uuid-alice",
            "type": "USER", "state": "StateActive"},
}


def make_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "tenant": "acme",
        "allowed_namespaces": ("prod", "staging", "shared"),
        "api_token": TOKEN,
        "rate_per_minute": 1000,
        "global_rate_per_minute": 1000,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


class FakeXC:
    """Routes: (METHOD, path) -> JSON payload, (status, payload) or callable(request)."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], Any] = {}
        self.requests: list[httpx.Request] = []
        self.users = dict(USERS)
        self.add("GET", WHOAMI, self._whoami)

    def _whoami(self, request: httpx.Request) -> httpx.Response:
        token = request.headers.get("authorization", "").removeprefix("APIToken ")
        user = self.users.get(token)
        return httpx.Response(200, json=user) if user else httpx.Response(401, json={"message": "unauthorized"})

    @property
    def api_requests(self) -> list[httpx.Request]:
        """Requests other than identity resolution."""
        return [r for r in self.requests if r.url.path != WHOAMI]

    def add(self, method: str, path: str, response: Any) -> None:
        self.routes[(method, path)] = response

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        route = self.routes.get((request.method, request.url.path))
        if route is None:
            return httpx.Response(404, json={"message": "not found"})
        if callable(route):
            route = route(request)
        if isinstance(route, httpx.Response):
            return route
        if isinstance(route, tuple):
            status, payload = route
            return httpx.Response(status, json=payload)
        return httpx.Response(200, json=route)

    def bodies(self, path: str) -> list[dict[str, Any]]:
        return [json.loads(r.content) for r in self.requests if r.url.path == path and r.content]


class Harness:
    def __init__(self, settings: Settings, xc: FakeXC) -> None:
        self.xc = xc
        self.audit_stream = io.StringIO()
        client = XCClient(settings, transport=httpx.MockTransport(xc.handler))
        self.runtime = Runtime(settings, client=client, audit=AuditLog(stream=self.audit_stream))
        self.mcp, _ = build_server(settings, self.runtime)

    def audit(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.audit_stream.getvalue().splitlines()]

    @asynccontextmanager
    async def session(self, elicitation_callback: Callable | None = None):
        async with create_connected_server_and_client_session(
            self.mcp, elicitation_callback=elicitation_callback
        ) as session:
            yield session

    async def call(self, tool: str, args: dict[str, Any] | None = None, **session_kwargs: Any):
        async with self.session(**session_kwargs) as session:
            return await session.call_tool(tool, args or {})


def result_json(result: Any) -> dict[str, Any]:
    assert not result.isError, result.content
    if result.structuredContent:
        return result.structuredContent.get("result", result.structuredContent)
    return json.loads(result.content[0].text)


def error_text(result: Any) -> str:
    assert result.isError, "expected an error"
    return result.content[0].text


@pytest.fixture
def xc() -> FakeXC:
    return FakeXC()


@pytest.fixture
def harness(xc: FakeXC) -> Harness:
    return Harness(make_settings(), xc)


@pytest.fixture
def write_harness(xc: FakeXC) -> Harness:
    return Harness(make_settings(mode="write", enable_writes=True), xc)
