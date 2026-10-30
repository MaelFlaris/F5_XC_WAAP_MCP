"""Streamable HTTP end to end: a real uvicorn server, the official MCP client.

Checks that the caller's own token (X-F5XC-API-Token) is the one sent to XC,
that a request without token is refused, and that a foreign Origin is rejected.
"""

import asyncio
import socket
import threading

import httpx
import pytest
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from f5xc_waap_mcp.config import Transport
from tests.conftest import FakeXC, Harness, make_settings

ALICE = "AliceOwnPersonalToken-000000000000"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def http_server():
    port = free_port()
    xc = FakeXC()
    xc.add("GET", "/api/config/namespaces/prod/app_firewalls", {"items": [{"name": "fw1"}]})
    settings = make_settings(transport=Transport.STREAMABLE_HTTP, api_token=None, bind_port=port,
                             allowed_origins=("https://mcp.example",))
    harness = Harness(settings, xc)
    server = uvicorn.Server(uvicorn.Config(harness.mcp.streamable_http_app(), host="127.0.0.1", port=port,
                                           log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        threading.Event().wait(0.05)
    yield f"http://127.0.0.1:{port}/mcp", xc, harness
    server.should_exit = True
    thread.join(5)


async def call(url: str, headers: dict[str, str]):
    async with streamablehttp_client(url, headers=headers) as (read, write, _), ClientSession(read, write) as session:
        await session.initialize()
        return await session.call_tool("list_objects", {"kind": "app_firewall", "namespace": "prod"})


async def test_token_of_the_caller_is_used(http_server):
    url, xc, harness = http_server
    result = await asyncio.wait_for(call(url, {"X-F5XC-API-Token": ALICE}), 20)
    assert not result.isError, result.content
    assert xc.requests[-1].headers["authorization"] == f"APIToken {ALICE}"
    assert harness.audit()[-1]["identity"].startswith("token:")


async def test_request_without_token_is_refused(http_server):
    url, xc, _ = http_server
    result = await asyncio.wait_for(call(url, {}), 20)
    assert result.isError and "unauthenticated" in result.content[0].text
    assert xc.requests == []


async def test_foreign_origin_is_rejected(http_server):
    url, _, _ = http_server
    async with httpx.AsyncClient() as client:
        response = await client.post(url, headers={"Origin": "https://evil.example", "Content-Type": "application/json",
                                                   "Accept": "application/json, text/event-stream"},
                                     content=b"{}")
    assert response.status_code == 403
