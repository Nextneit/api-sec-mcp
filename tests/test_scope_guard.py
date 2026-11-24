"""
Tests for ScopeGuard — deny-by-default allowlist enforcement.

All DNS resolution is faked; no real network calls are made.
Run with: pytest tests/test_scope_guard.py
"""
import ipaddress

import pytest

from api_sec_mcp.egress.scope_guard import (
    CheckResult,
    ScopeConfig,
    ScopeGuard,
    ScopeViolationError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def fake_resolver(mapping: dict[str, list[str]]):
    """Resolver stub — raises OSError on unknown hosts."""

    def _resolve(host: str) -> list[str]:
        if host not in mapping:
            raise OSError(f"[test] no record for {host!r}")
        return mapping[host]

    return _resolve


def guard(
    *,
    hosts: list[str] | None = None,
    ips: list[str] | None = None,
    ports: list[int] | None = None,
    schemes: list[str] | None = None,
    resolver=None,
) -> ScopeGuard:
    """Build a ScopeGuard with minimal boilerplate."""
    cfg = ScopeConfig(
        allowed_hosts=hosts or [],
        allowed_ips=ips or [],
        allowed_ports=ports or [80, 443, 8080],
        allowed_schemes=schemes or ["https", "http"],
    )
    # Default resolver: any hostname → a public non-restricted IP
    return ScopeGuard(cfg, resolver=resolver or (lambda _: ["203.0.113.1"]))


# ---------------------------------------------------------------------------
# 1. Cloud metadata and link-local — always blocked, no override possible
# ---------------------------------------------------------------------------


class TestLinkLocalAndCloudMetadata:
    def test_ipv4_link_local_blocked(self):
        g = guard()
        with pytest.raises(ScopeViolationError, match="always-blocked"):
            g.check("http://169.254.0.1/")

    def test_cloud_metadata_endpoint_blocked(self):
        g = guard()
        with pytest.raises(ScopeViolationError, match="always-blocked"):
            g.check("http://169.254.169.254/")

    def test_ipv6_link_local_blocked(self):
        g = guard()
        with pytest.raises(ScopeViolationError, match="always-blocked"):
            g.check("http://[fe80::1]/")

    def test_ipv4_mapped_link_local_blocked(self):
        """::ffff:169.254.x.x maps to IPv4 link-local — must be blocked."""
        g = guard()
        with pytest.raises(ScopeViolationError, match="always-blocked"):
            g.check("http://[::ffff:169.254.169.254]/")

    def test_link_local_in_allowed_ips_still_blocked(self):
        """allowed_ips cannot override the link-local hard block."""
        g = guard(ips=["169.254.0.0/16"])
        with pytest.raises(ScopeViolationError, match="always-blocked"):
            g.check("http://169.254.0.1/")

    def test_link_local_resolved_hostname_blocked(self):
        """Host in allowed_hosts that resolves to link-local is blocked."""
        g = guard(
            hosts=["api.example.com"],
            resolver=fake_resolver({"api.example.com": ["169.254.1.1"]}),
        )
        with pytest.raises(ScopeViolationError, match="always-blocked"):
            g.check("https://api.example.com/")


# ---------------------------------------------------------------------------
# 2. Loopback — blocked unless explicitly in scope
# ---------------------------------------------------------------------------


class TestLoopback:
    def test_loopback_blocked_by_default(self):
        g = guard()
        with pytest.raises(ScopeViolationError):
            g.check("http://127.0.0.1/")

    def test_loopback_allowed_when_explicit_ip_in_scope(self):
        g = guard(ips=["127.0.0.1"])
        result = g.check("http://127.0.0.1/")
        assert result.resolved_ip == "127.0.0.1"

    def test_loopback_cidr_allowed_when_in_scope(self):
        g = guard(ips=["127.0.0.0/8"])
        result = g.check("http://127.0.0.2/")
        assert result.resolved_ip == "127.0.0.2"

    def test_ipv6_loopback_blocked_by_default(self):
        g = guard()
        with pytest.raises(ScopeViolationError):
            g.check("http://[::1]/")

    def test_ipv6_loopback_allowed_when_in_scope(self):
        g = guard(ips=["::1"])
        result = g.check("http://[::1]/")
        assert result.resolved_ip == "::1"


# ---------------------------------------------------------------------------
# 3. Alternate IP encodings — decimal, hex, octal
# ---------------------------------------------------------------------------


class TestAlternateIPEncodings:
    def test_decimal_integer_loopback_blocked(self):
        """2130706433 == 127.0.0.1"""
        g = guard()
        with pytest.raises(ScopeViolationError):
            g.check("http://2130706433/")

    def test_decimal_integer_loopback_allowed_when_in_scope(self):
        g = guard(ips=["127.0.0.1"])
        result = g.check("http://2130706433/")
        assert ipaddress.ip_address(result.resolved_ip) == ipaddress.ip_address("127.0.0.1")

    def test_hex_integer_loopback_blocked(self):
        """0x7f000001 == 127.0.0.1"""
        g = guard()
        with pytest.raises(ScopeViolationError):
            g.check("http://0x7f000001/")

    def test_hex_integer_loopback_allowed_when_in_scope(self):
        g = guard(ips=["127.0.0.1"])
        result = g.check("http://0x7f000001/")
        assert ipaddress.ip_address(result.resolved_ip) == ipaddress.ip_address("127.0.0.1")

    def test_octal_first_octet_loopback_blocked(self):
        """0177.0.0.1 — first octet in octal (0177₈ == 127) == 127.0.0.1"""
        g = guard()
        with pytest.raises(ScopeViolationError):
            g.check("http://0177.0.0.1/")

    def test_decimal_link_local_always_blocked_even_in_allowed_ips(self):
        """2852039166 == 169.254.169.254 — always blocked regardless of allowed_ips."""
        g = guard(ips=["169.254.0.0/16"])
        with pytest.raises(ScopeViolationError, match="always-blocked"):
            g.check("http://2852039166/")


# ---------------------------------------------------------------------------
# 4. IPv6 and IPv4-mapped addresses
# ---------------------------------------------------------------------------


class TestIPv6AndMappedAddresses:
    def test_ipv6_loopback_mapped_blocked(self):
        """::ffff:127.0.0.1 maps to 127.0.0.1 (loopback) — blocked."""
        g = guard()
        with pytest.raises(ScopeViolationError):
            g.check("http://[::ffff:127.0.0.1]/")

    def test_ipv6_loopback_mapped_allowed_when_loopback_in_scope(self):
        g = guard(ips=["127.0.0.1"])
        result = g.check("http://[::ffff:127.0.0.1]/")
        # resolved_ip is the IPv6 form; its mapped IPv4 must equal 127.0.0.1
        mapped = ipaddress.ip_address(result.resolved_ip)
        assert isinstance(mapped, ipaddress.IPv6Address)
        assert mapped.ipv4_mapped == ipaddress.IPv4Address("127.0.0.1")

    def test_ipv6_loopback_itself_blocked(self):
        g = guard()
        with pytest.raises(ScopeViolationError):
            g.check("http://[::1]/")

    def test_ipv6_documentation_range_blocked_if_not_in_scope(self):
        """Direct IPv6 URL — must be in allowed_ips even if public-ish."""
        g = guard()
        with pytest.raises(ScopeViolationError):
            g.check("http://[2001:db8::1]/")

    def test_ipv6_in_allowed_ips_ok(self):
        g = guard(ips=["2001:db8::1"])
        result = g.check("http://[2001:db8::1]/")
        assert ipaddress.ip_address(result.resolved_ip) == ipaddress.ip_address("2001:db8::1")


# ---------------------------------------------------------------------------
# 5. Non-http(s) schemes — always rejected
# ---------------------------------------------------------------------------


class TestSchemes:
    @pytest.mark.parametrize(
        "url",
        [
            "file:///etc/passwd",
            "gopher://evil.com/",
            "ftp://evil.com/",
            "data:text/html,<h1>XSS</h1>",
            "javascript:alert(1)",
        ],
    )
    def test_non_http_scheme_blocked(self, url: str):
        g = guard()
        with pytest.raises(ScopeViolationError):
            g.check(url)

    def test_https_allowed(self):
        g = guard(
            hosts=["api.example.com"],
            resolver=fake_resolver({"api.example.com": ["203.0.113.1"]}),
        )
        result = g.check("https://api.example.com/")
        assert result.scheme == "https"

    def test_http_blocked_when_only_https_in_scope(self):
        g = guard(
            schemes=["https"],
            hosts=["api.example.com"],
            resolver=fake_resolver({"api.example.com": ["203.0.113.1"]}),
        )
        with pytest.raises(ScopeViolationError, match="[Ss]cheme"):
            g.check("http://api.example.com/")


# ---------------------------------------------------------------------------
# 6. Userinfo and malformed URLs
# ---------------------------------------------------------------------------


class TestMalformedURLs:
    def test_userinfo_rejected(self):
        g = guard(hosts=["example.com"])
        with pytest.raises(ScopeViolationError, match="[Uu]serinfo"):
            g.check("http://user@example.com/")

    def test_userinfo_with_password_rejected(self):
        g = guard(hosts=["example.com"])
        with pytest.raises(ScopeViolationError, match="[Uu]serinfo"):
            g.check("http://user:pass@example.com/")

    def test_no_host_rejected(self):
        g = guard()
        with pytest.raises(ScopeViolationError):
            g.check("http://")

    def test_no_scheme_rejected(self):
        g = guard()
        with pytest.raises(ScopeViolationError):
            g.check("not-a-url")

    def test_empty_string_rejected(self):
        g = guard()
        with pytest.raises(ScopeViolationError):
            g.check("")


# ---------------------------------------------------------------------------
# 7. Port enforcement
# ---------------------------------------------------------------------------


class TestPorts:
    def test_port_not_in_list_blocked(self):
        g = guard(
            ports=[443],
            hosts=["api.example.com"],
            resolver=fake_resolver({"api.example.com": ["203.0.113.1"]}),
        )
        with pytest.raises(ScopeViolationError, match="[Pp]ort"):
            g.check("https://api.example.com:9999/")

    def test_port_in_list_ok(self):
        g = guard(
            ports=[8080],
            hosts=["api.example.com"],
            resolver=fake_resolver({"api.example.com": ["203.0.113.1"]}),
        )
        result = g.check("http://api.example.com:8080/")
        assert result.port == 8080

    def test_implicit_https_port_443_ok(self):
        g = guard(
            ports=[443],
            hosts=["api.example.com"],
            resolver=fake_resolver({"api.example.com": ["203.0.113.1"]}),
        )
        result = g.check("https://api.example.com/")
        assert result.port == 443

    def test_implicit_http_port_80_ok(self):
        g = guard(
            ports=[80],
            hosts=["api.example.com"],
            resolver=fake_resolver({"api.example.com": ["203.0.113.1"]}),
        )
        result = g.check("http://api.example.com/")
        assert result.port == 80


# ---------------------------------------------------------------------------
# 8. Hostname resolves to a disallowed IP — blocked
# ---------------------------------------------------------------------------


class TestHostnameResolvesToDisallowedIP:
    def test_allowed_host_resolves_to_private_ip_blocked(self):
        g = guard(
            hosts=["api.example.com"],
            resolver=fake_resolver({"api.example.com": ["10.0.0.1"]}),
        )
        with pytest.raises(ScopeViolationError):
            g.check("https://api.example.com/")

    def test_allowed_host_resolves_to_loopback_blocked(self):
        g = guard(
            hosts=["api.example.com"],
            resolver=fake_resolver({"api.example.com": ["127.0.0.1"]}),
        )
        with pytest.raises(ScopeViolationError):
            g.check("https://api.example.com/")

    def test_allowed_host_resolves_to_link_local_blocked(self):
        g = guard(
            hosts=["api.example.com"],
            resolver=fake_resolver({"api.example.com": ["169.254.1.1"]}),
        )
        with pytest.raises(ScopeViolationError, match="always-blocked"):
            g.check("https://api.example.com/")

    def test_host_not_in_allowlist_blocked_regardless_of_ip(self):
        """A hostname not in allowed_hosts is blocked even with a public IP."""
        g = guard(
            hosts=["api.example.com"],
            resolver=fake_resolver({"evil.example.com": ["203.0.113.1"]}),
        )
        with pytest.raises(ScopeViolationError):
            g.check("https://evil.example.com/")


# ---------------------------------------------------------------------------
# 9. Explicit allowlist — hostname + IP/CIDR combinations
# ---------------------------------------------------------------------------


class TestExplicitAllowlist:
    def test_allowed_host_with_public_ip_ok(self):
        g = guard(
            hosts=["api.example.com"],
            resolver=fake_resolver({"api.example.com": ["203.0.113.1"]}),
        )
        result = g.check("https://api.example.com/")
        assert result.resolved_ip == "203.0.113.1"
        assert result.host == "api.example.com"
        assert result.scheme == "https"

    def test_docker_private_network_via_cidr_ok(self):
        """A private Docker network can be authorized via CIDR in allowed_ips."""
        g = guard(
            hosts=["my-service"],
            ips=["172.20.0.0/16"],
            ports=[80],
            resolver=fake_resolver({"my-service": ["172.20.0.5"]}),
        )
        result = g.check("http://my-service/")
        assert result.resolved_ip == "172.20.0.5"

    def test_loopback_allowed_via_explicit_single_ip(self):
        g = guard(ips=["127.0.0.1"])
        result = g.check("http://127.0.0.1/")
        assert result.resolved_ip == "127.0.0.1"

    def test_direct_public_ip_in_url_requires_allowed_ips(self):
        """A direct IP URL must have the IP in allowed_ips — hostname allowlist is irrelevant."""
        g = guard(hosts=["api.example.com"])  # host allowed, but no allowed_ips
        with pytest.raises(ScopeViolationError):
            g.check("http://203.0.113.1/")

    def test_direct_public_ip_in_url_ok_when_in_allowed_ips(self):
        g = guard(ips=["203.0.113.1"])
        result = g.check("http://203.0.113.1/")
        assert result.resolved_ip == "203.0.113.1"

    def test_check_result_is_named_tuple(self):
        g = guard(
            hosts=["api.example.com"],
            resolver=fake_resolver({"api.example.com": ["203.0.113.1"]}),
        )
        result = g.check("https://api.example.com/path?q=1")
        assert isinstance(result, CheckResult)
        assert result.scheme == "https"
        assert result.host == "api.example.com"
        assert result.port == 443


# ---------------------------------------------------------------------------
# 10. All resolved IPs must pass — DNS rebinding / multi-A
# ---------------------------------------------------------------------------


class TestAllIPsMustBeValid:
    def test_one_bad_ip_blocks_entire_resolution(self):
        """Host returns one good and one private IP — entire request blocked."""
        g = guard(
            hosts=["api.example.com"],
            resolver=fake_resolver({"api.example.com": ["203.0.113.1", "10.0.0.1"]}),
        )
        with pytest.raises(ScopeViolationError):
            g.check("https://api.example.com/")

    def test_all_ips_good_allowed(self):
        """Multiple good IPs — first one becomes resolved_ip."""
        g = guard(
            hosts=["api.example.com"],
            resolver=fake_resolver({"api.example.com": ["203.0.113.1", "203.0.113.2"]}),
        )
        result = g.check("https://api.example.com/")
        assert result.resolved_ip in {"203.0.113.1", "203.0.113.2"}

    def test_resolver_called_exactly_once(self):
        """DNS resolution must happen exactly once per check() call."""
        call_count = 0

        def counting_resolver(host: str) -> list[str]:
            nonlocal call_count
            call_count += 1
            return ["203.0.113.1"]

        g = guard(hosts=["api.example.com"], resolver=counting_resolver)
        g.check("https://api.example.com/")
        assert call_count == 1

    def test_one_link_local_ip_blocks_even_with_good_sibling(self):
        """If any resolved IP is link-local the whole request is blocked."""
        g = guard(
            hosts=["api.example.com"],
            resolver=fake_resolver({"api.example.com": ["203.0.113.1", "169.254.0.1"]}),
        )
        with pytest.raises(ScopeViolationError, match="always-blocked"):
            g.check("https://api.example.com/")
