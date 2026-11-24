"""
Tests for EgressClient — safe HTTP communication with ScopeGuard enforcement.

Tests strictly use httpx.MockTransport; no real network connections are made.
"""

import httpx
import pytest

from api_sec_mcp.egress.client import EgressClient, EgressResponse, ResponseTooLargeError
from api_sec_mcp.egress.scope_guard import ScopeConfig, ScopeGuard, ScopeViolationError


def make_guard(
    hosts: list[str] | None = None,
    ips: list[str] | None = None,
    ports: list[int] | None = None,
    schemes: list[str] | None = None,
    ip_mapping: dict[str, list[str]] | None = None,
) -> ScopeGuard:
    """Helper to instantiate ScopeGuard with controlled fake DNS."""
    # If host not in mapping, simulate DNS returning an IP not in allowed scope
    mapping = ip_mapping or {"api.example.com": ["203.0.113.10"]}
    cfg = ScopeConfig(
        allowed_hosts=hosts or ["api.example.com"],
        allowed_ips=ips or ["203.0.113.10"],
        allowed_ports=ports or [80, 443, 8080],
        allowed_schemes=schemes or ["https", "http"],
    )
    return ScopeGuard(cfg, resolver=lambda h: mapping.get(h, ["198.51.100.1"]))


class TestEgressClientScopeEnforcement:
    async def test_blocked_url_raises_before_http_request(self):
        guard = make_guard(hosts=["api.example.com"])
        client = EgressClient(scope_guard=guard)

        # Attempt to reach link-local metadata
        with pytest.raises(ScopeViolationError, match="always-blocked"):
            await client.get("http://169.254.169.254/latest/meta-data/")

    async def test_unauthorized_host_raises_scope_violation(self):
        guard = make_guard(hosts=["api.example.com"])
        client = EgressClient(scope_guard=guard)

        with pytest.raises(ScopeViolationError):
            await client.get("https://unauthorized.com/")


class TestEgressClientSecurityBehaviors:
    async def test_connects_to_resolved_ip_with_host_header(self):
        """Verifies that the request uses the resolved IP and preserves the Host header."""
        guard = make_guard(
            hosts=["api.example.com"],
            ips=["203.0.113.10"],
            ip_mapping={"api.example.com": ["203.0.113.10"]},
        )

        captured_request: httpx.Request | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_request
            captured_request = request
            return httpx.Response(200, headers={"Server": "test-srv"}, text="ok")

        transport = httpx.MockTransport(handler)
        client = EgressClient(scope_guard=guard, transport=transport)

        res = await client.get("https://api.example.com/v1/health")

        assert isinstance(res, EgressResponse)
        assert res.status_code == 200
        assert captured_request is not None
        # Host header must be the original hostname
        assert captured_request.headers["host"] == "api.example.com"
        # The actual requested URL host target in transport is the resolved IP
        assert captured_request.url.host == "203.0.113.10"

    async def test_redirects_are_not_followed(self):
        """follow_redirects must strictly be False."""
        guard = make_guard(hosts=["api.example.com"])

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(302, headers={"Location": "http://169.254.169.254/"})

        transport = httpx.MockTransport(handler)
        client = EgressClient(scope_guard=guard, transport=transport)

        res = await client.get("https://api.example.com/redirect")
        # Must return the 302 without following to Location
        assert res.status_code == 302
        assert "location" in res.headers

    async def test_max_response_bytes_limit_enforced(self):
        """Client must reject responses exceeding max_response_bytes."""
        guard = make_guard(hosts=["api.example.com"])

        def handler(request: httpx.Request) -> httpx.Response:
            # 100 bytes payload
            return httpx.Response(200, content=b"A" * 100)

        transport = httpx.MockTransport(handler)
        # Limit to 50 bytes
        client = EgressClient(scope_guard=guard, transport=transport, max_response_bytes=50)

        with pytest.raises(ResponseTooLargeError):
            await client.get("https://api.example.com/large")

    async def test_headers_are_extracted_cleanly(self):
        """Headers are accessible as lowercase dict."""
        guard = make_guard(hosts=["api.example.com"])

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={
                    "Content-Type": "application/json",
                    "X-Custom-Header": "value123",
                },
                content=b"{}",
            )

        transport = httpx.MockTransport(handler)
        client = EgressClient(scope_guard=guard, transport=transport)

        res = await client.get("https://api.example.com/data")
        assert res.headers["content-type"] == "application/json"
        assert res.headers["x-custom-header"] == "value123"
