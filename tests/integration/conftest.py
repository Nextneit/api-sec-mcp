"""Harness: real uvicorn lab on an ephemeral loopback port + real MCP client."""

import threading
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import pytest
import uvicorn
from fastmcp import Client

from api_sec_mcp import server
from api_sec_mcp.egress.scope_guard import ScopeConfig, ScopeGuard


class CountingMiddleware:
    """ASGI middleware owned by the harness: counts requests reaching the lab."""

    def __init__(self, app, counter: Counter) -> None:
        self.app = app
        self.counter = counter

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            self.counter[scope["path"]] += 1
        await self.app(scope, receive, send)


@dataclass
class Lab:
    base: str
    port: int
    counter: Counter

    @property
    def total(self) -> int:
        return sum(self.counter.values())


@dataclass
class Engagement:
    client: server.EgressClient
    log_path: Path


@pytest.fixture(scope="session")
def lab():
    from target.app import app

    counter: Counter = Counter()
    config = uvicorn.Config(
        CountingMiddleware(app, counter), host="127.0.0.1", port=0, log_level="warning",
        server_header=False, date_header=False, timeout_graceful_shutdown=1, lifespan="off",
    )
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not srv.started:
        assert time.monotonic() < deadline, "lab did not start"
        time.sleep(0.02)
    port = srv.servers[0].sockets[0].getsockname()[1]
    yield Lab(base=f"http://127.0.0.1:{port}", port=port, counter=counter)
    srv.should_exit = True
    thread.join(10)
    assert not thread.is_alive(), "lab did not stop"


@pytest.fixture
def engagement(lab, tmp_path, monkeypatch):
    """Factory: build a real egress client (real resolver/sockets) authorizing only the lab."""

    def make(**overrides) -> Engagement:
        params = {
            "allowed_ips": ["127.0.0.1"], "allowed_ports": [lab.port], "allowed_schemes": ["http"],
            "audit_log_path": str(tmp_path / "audit.jsonl"),
            "max_response_bytes": 100_000, "request_timeout_seconds": 5,
        }
        params.update(overrides)
        client = server.build_egress_client(ScopeGuard(ScopeConfig(**params)))
        monkeypatch.setattr(server, "_CLIENT", client)
        return Engagement(client=client, log_path=tmp_path / "audit.jsonl")

    return make


async def call_tool(name: str, args: dict) -> dict:
    """Invoke a tool through the real MCP protocol (in-memory transport)."""
    async with Client(server.mcp) as c:
        return (await c.call_tool(name, args)).data
