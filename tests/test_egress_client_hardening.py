"""
Hardening tests for EgressClient.

Enforces:
1. SNI extension & TLS verification configuration.
2. Max response limits: Content-Length check, streaming cutoff, gzip expansion, boundary conditions.
3. No bypass to ScopeGuard across all public methods.
4. Safe redirect handling: follow_redirects=False, no extra requests, sanitized Location.
5. Header preservation & multi-value headers (e.g. Set-Cookie list), non-ASCII/oversized headers.
6. IPv6 bracket preservation, port/path/query preservation, timeout wrapping, clean error messages.
"""

import gzip

import httpx
import pytest

from api_sec_mcp.egress.client import (
    EgressClient,
    EgressTimeoutError,
    ResponseTooLargeError,
)
from api_sec_mcp.egress.scope_guard import ScopeConfig, ScopeGuard, ScopeViolationError


def make_guard(
    hosts: list[str] | None = None,
    ips: list[str] | None = None,
    ports: list[int] | None = None,
    schemes: list[str] | None = None,
    ip_mapping: dict[str, list[str]] | None = None,
) -> ScopeGuard:
    mapping = ip_mapping or {"api.example.com": ["203.0.113.10"]}
    cfg = ScopeConfig(
        allowed_hosts=hosts or ["api.example.com"],
        allowed_ips=ips or ["203.0.113.10"],
        allowed_ports=ports or [80, 443, 8080, 8443],
        allowed_schemes=schemes or ["https", "http"],
    )
    return ScopeGuard(cfg, resolver=lambda h: mapping.get(h, ["198.51.100.1"]))


# ---------------------------------------------------------------------------
# 1. SNI y TLS
# ---------------------------------------------------------------------------


class TestSniAndTls:
    async def test_sni_hostname_passed_in_request_extensions(self):
        """Request must include extensions['sni_hostname'] set to original hostname."""
        guard = make_guard(
            hosts=["api.example.com"],
            ips=["203.0.113.10"],
            ip_mapping={"api.example.com": ["203.0.113.10"]},
        )
        captured_req: httpx.Request | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_req
            captured_req = request
            return httpx.Response(200, content=b"ok")

        client = EgressClient(scope_guard=guard, transport=httpx.MockTransport(handler))
        await client.get("https://api.example.com/test")

        assert captured_req is not None
        assert captured_req.url.host == "203.0.113.10"
        assert captured_req.extensions.get("sni_hostname") == "api.example.com"

    async def test_verify_is_not_disabled(self):
        """EgressClient must not instantiate AsyncClient with verify=False."""
        guard = make_guard()
        client = EgressClient(scope_guard=guard)
        # Verify default verify configuration attribute
        assert client.verify is True or client.verify is not False


# ---------------------------------------------------------------------------
# 2. Límite de tamaño real
# ---------------------------------------------------------------------------


class TestSizeLimits:
    async def test_content_length_exceeding_limit_aborts_without_reading_body(self):
        """If declared Content-Length exceeds max_response_bytes, reject immediately."""
        guard = make_guard()
        body_read = False

        async def async_body_generator():
            nonlocal body_read
            body_read = True
            yield b"too large content"

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Length": "10485760"},  # 10 MB declared
                content=async_body_generator(),
            )

        client = EgressClient(
            scope_guard=guard,
            transport=httpx.MockTransport(handler),
            max_response_bytes=100,
        )

        with pytest.raises(ResponseTooLargeError):
            await client.get("https://api.example.com/huge")

        assert body_read is False

    async def test_streaming_generator_cut_off_at_limit(self):
        """An infinite chunk generator is terminated once max_response_bytes is exceeded."""
        guard = make_guard()
        chunks_produced = 0

        async def infinite_stream():
            nonlocal chunks_produced
            while True:
                chunks_produced += 1
                yield b"A" * 50

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=infinite_stream())

        client = EgressClient(
            scope_guard=guard,
            transport=httpx.MockTransport(handler),
            max_response_bytes=120,
        )

        with pytest.raises(ResponseTooLargeError):
            await client.get("https://api.example.com/infinite")

        # Must cut off after 3 chunks (150 bytes > 120 bytes), without consuming infinitely
        assert 1 <= chunks_produced <= 5

    async def test_gzip_expansion_limit_applied_to_decompressed_bytes(self):
        """Gzip bomb: small compressed payload that expands beyond limit is rejected."""
        guard = make_guard()
        # Compress 10,000 bytes into a small gzip payload
        decompressed_data = b"0" * 10000
        compressed_data = gzip.compress(decompressed_data)
        assert len(compressed_data) < 200

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Encoding": "gzip"},
                content=compressed_data,
            )

        client = EgressClient(
            scope_guard=guard,
            transport=httpx.MockTransport(handler),
            max_response_bytes=500,  # Smaller than decompressed 10,000
        )

        with pytest.raises(ResponseTooLargeError):
            await client.get("https://api.example.com/gzip-bomb")

    async def test_response_exactly_at_limit_is_accepted(self):
        """Response whose size is exactly max_response_bytes succeeds."""
        guard = make_guard()
        exact_bytes = b"X" * 100

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=exact_bytes)

        client = EgressClient(
            scope_guard=guard,
            transport=httpx.MockTransport(handler),
            max_response_bytes=100,
        )

        res = await client.get("https://api.example.com/exact")
        assert len(res.content) == 100


# ---------------------------------------------------------------------------
# 3. No hay atajo al ScopeGuard
# ---------------------------------------------------------------------------


class TestNoScopeGuardBypass:
    @pytest.mark.parametrize("method_name", ["get", "head", "options", "request"])
    async def test_all_public_methods_block_when_scope_violated(self, method_name: str):
        """No public method can bypass ScopeGuard check."""
        cfg = ScopeConfig(allowed_hosts=["api.example.com"])
        # Guard that always raises ScopeViolationError
        guard = ScopeGuard(cfg, resolver=lambda h: ["192.168.1.1"])

        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(200, content=b"ok")

        client = EgressClient(scope_guard=guard, transport=httpx.MockTransport(handler))

        with pytest.raises(ScopeViolationError):
            if method_name == "request":
                await client.request("GET", "https://unauthorized.com/")
            else:
                method = getattr(client, method_name)
                await method("https://unauthorized.com/")

        assert call_count == 0


# ---------------------------------------------------------------------------
# 4. Redirects
# ---------------------------------------------------------------------------


class TestRedirects:
    @pytest.mark.parametrize("status_code", [301, 302, 307])
    async def test_redirect_returns_single_response_without_following(self, status_code: int):
        guard = make_guard()
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(status_code, headers={"Location": "https://api.example.com/other"})

        client = EgressClient(scope_guard=guard, transport=httpx.MockTransport(handler))
        res = await client.get("https://api.example.com/redir")

        assert res.status_code == status_code
        assert call_count == 1

    async def test_redirect_to_cloud_metadata_makes_no_extra_request(self):
        """Redirect pointing to cloud metadata causes zero subsequent calls."""
        guard = make_guard()
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})

        client = EgressClient(scope_guard=guard, transport=httpx.MockTransport(handler))
        res = await client.get("https://api.example.com/redir-ssrf")

        assert res.status_code == 302
        assert call_count == 1

    async def test_location_header_behavior(self):
        """
        Documented behavior: Location header is present in headers mapping as sanitized / raw string
        extracted from response headers.
        """
        guard = make_guard()

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(302, headers={"Location": "/safe-path"})

        client = EgressClient(scope_guard=guard, transport=httpx.MockTransport(handler))
        res = await client.get("https://api.example.com/redirect-check")
        assert res.headers.get("location") == "/safe-path"


# ---------------------------------------------------------------------------
# 5. Cabeceras
# ---------------------------------------------------------------------------


class TestHeadersHandling:
    async def test_duplicate_headers_preserved_as_list(self):
        """Multiple headers with the same name (e.g. Set-Cookie) must not be lost."""
        guard = make_guard()

        # In raw ASGI/HTTP, headers can have duplicate keys
        raw_headers = [
            (b"set-cookie", b"cookie1=val1; Path=/"),
            (b"set-cookie", b"cookie2=val2; Path=/"),
            (b"server", b"test-srv"),
        ]

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers=raw_headers, content=b"ok")

        client = EgressClient(scope_guard=guard, transport=httpx.MockTransport(handler))
        res = await client.get("https://api.example.com/cookies")

        # Check that multiple values are retained
        cookies = res.multi_headers.get("set-cookie")
        assert cookies is not None
        assert len(cookies) == 2
        assert "cookie1=val1; Path=/" in cookies
        assert "cookie2=val2; Path=/" in cookies

    async def test_non_ascii_and_oversized_header_handled_gracefully(self):
        """Non-ASCII (raw bytes) and large headers do not crash the client."""
        guard = make_guard()
        large_header_value = "A" * 4096

        raw_headers = [
            (b"x-large", large_header_value.encode("ascii")),
            (b"x-utf8", "café-protegé".encode()),
        ]

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers=raw_headers,
                content=b"ok",
            )

        client = EgressClient(scope_guard=guard, transport=httpx.MockTransport(handler))
        res = await client.get("https://api.example.com/special-headers")
        assert res.status_code == 200
        assert res.headers["x-large"] == large_header_value
        assert "x-utf8" in res.headers


# ---------------------------------------------------------------------------
# 6. Otros
# ---------------------------------------------------------------------------


class TestAdditionalHardening:
    async def test_ipv6_direct_ip_url_construction(self):
        """IPv6 URL retains brackets, port, path and query."""
        guard = make_guard(
            ips=["::1"],
            ports=[8080],
            schemes=["http"],
        )
        captured_req: httpx.Request | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_req
            captured_req = request
            return httpx.Response(200, content=b"ok")

        client = EgressClient(scope_guard=guard, transport=httpx.MockTransport(handler))
        await client.get("http://[::1]:8080/api/v1?query=test#frag")

        assert captured_req is not None
        assert captured_req.url.host == "::1"
        assert captured_req.url.port == 8080
        assert captured_req.url.path == "/api/v1"
        assert captured_req.url.query == b"query=test"

    async def test_hostname_with_custom_port_path_query_preserved_when_ip_rewritten(self):
        """Host rewritten to IP preserves custom port, path, query and Host header."""
        guard = make_guard(
            hosts=["api.example.com"],
            ips=["203.0.113.10"],
            ports=[8443],
            ip_mapping={"api.example.com": ["203.0.113.10"]},
        )
        captured_req: httpx.Request | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_req
            captured_req = request
            return httpx.Response(200, content=b"ok")

        client = EgressClient(scope_guard=guard, transport=httpx.MockTransport(handler))
        await client.get("https://api.example.com:8443/v2/items?filter=active")

        assert captured_req is not None
        assert captured_req.url.host == "203.0.113.10"
        assert captured_req.url.port == 8443
        assert captured_req.url.path == "/v2/items"
        assert captured_req.url.query == b"filter=active"
        assert captured_req.headers["host"] == "api.example.com:8443"

    async def test_timeout_raises_egress_timeout_error(self):
        """Timeout produces wrapped EgressTimeoutError and does not hang."""
        guard = make_guard()

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("Read timed out")

        client = EgressClient(scope_guard=guard, transport=httpx.MockTransport(handler))

        with pytest.raises(EgressTimeoutError):
            await client.get("https://api.example.com/timeout")

    async def test_clean_error_messages_contain_no_body_or_raw_headers(self):
        """Exceptions do not leak raw response headers or sensitive body text in error string."""
        guard = make_guard()

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Length": "1000", "X-Secret": "sensitive_leak"},
                content=b"SUPER_SECRET_INTERNAL_TOKEN",
            )

        client = EgressClient(
            scope_guard=guard,
            transport=httpx.MockTransport(handler),
            max_response_bytes=10,
        )

        with pytest.raises(ResponseTooLargeError) as exc_info:
            await client.get("https://api.example.com/leak-test")

        err_msg = str(exc_info.value)
        assert "SUPER_SECRET" not in err_msg
        assert "sensitive_leak" not in err_msg

    def test_multi_ip_resolution_pins_first_valid_ip_documented(self):
        """
        Documented behavior: When DNS resolves multiple IPs, ScopeGuard validates all.
        The first validated IP is pinned in CheckResult.resolved_ip for connection.
        If any resolved IP is disallowed, the whole check fails.
        """
        cfg = ScopeConfig(
            allowed_hosts=["api.example.com"],
            allowed_ips=["203.0.113.10", "203.0.113.11"],
            allowed_ports=[443],
            allowed_schemes=["https"],
        )
        # All valid
        guard_ok = ScopeGuard(cfg, resolver=lambda h: ["203.0.113.10", "203.0.113.11"])
        res = guard_ok.check("https://api.example.com/")
        assert res.resolved_ip == "203.0.113.10"

        # One disallowed IP in resolution -> blocks entire resolution
        guard_blocked = ScopeGuard(cfg, resolver=lambda h: ["203.0.113.10", "10.0.0.1"])
        with pytest.raises(ScopeViolationError):
            guard_blocked.check("https://api.example.com/")
