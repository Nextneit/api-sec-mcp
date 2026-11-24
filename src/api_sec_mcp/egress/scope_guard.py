"""
ScopeGuard — deny-by-default allowlist enforcement for HTTP targets.

This module is intentionally independent of FastMCP and httpx; it can be
tested and reused as a standalone library.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from typing import NamedTuple
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Always-blocked ranges — cannot be overridden by allowed_ips
# ---------------------------------------------------------------------------

_ALWAYS_BLOCKED_V4: list[ipaddress.IPv4Network] = [
    ipaddress.ip_network("169.254.0.0/16"),  # IPv4 link-local (incl. cloud metadata)
]
_ALWAYS_BLOCKED_V6: list[ipaddress.IPv6Network] = [
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
    ipaddress.ip_network("fec0::/10"),  # IPv6 site-local (deprecated, still observed)
]

# Restricted ranges — blocked unless explicitly listed in allowed_ips.
# Defined explicitly to avoid relying on ipaddress.is_global() semantics,
# which changed between Python versions and treats documentation ranges as
# non-global.
_RESTRICTED_V4: list[ipaddress.IPv4Network] = [
    ipaddress.ip_network("0.0.0.0/8"),        # "This" network (RFC 1122)
    ipaddress.ip_network("10.0.0.0/8"),        # Private-use (RFC 1918)
    ipaddress.ip_network("100.64.0.0/10"),     # Shared address space (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback (RFC 1122)
    ipaddress.ip_network("172.16.0.0/12"),     # Private-use (RFC 1918)
    ipaddress.ip_network("192.0.0.0/24"),      # IETF protocol assignments (RFC 6890)
    ipaddress.ip_network("192.168.0.0/16"),    # Private-use (RFC 1918)
    ipaddress.ip_network("198.18.0.0/15"),     # Benchmarking (RFC 2544)
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved (RFC 1112)
    ipaddress.ip_network("255.255.255.255/32"),# Limited broadcast
]
_RESTRICTED_V6: list[ipaddress.IPv6Network] = [
    ipaddress.ip_network("::1/128"),           # Loopback
    ipaddress.ip_network("fc00::/7"),          # Unique local (RFC 4193)
    ipaddress.ip_network("100::/64"),          # Discard prefix (RFC 6666)
]


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


class ScopeConfig(BaseModel):
    """Serialisable scope configuration; typically loaded from scope.yaml."""

    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_ips: list[str] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=list)
    allowed_schemes: list[str] = Field(default=["https"])
    max_response_bytes: int = Field(default=1_048_576, gt=0)
    request_timeout_seconds: int = Field(default=10, gt=0)
    audit_log_path: str = Field(default="audit.jsonl", min_length=1)
    max_requests_total: int = Field(default=1000, gt=0)
    max_requests_per_host_per_minute: int = Field(default=60, gt=0)
    max_concurrent_requests: int = Field(default=4, gt=0)
    run_label: str | None = None
    results_dir: str = Field(default="results", min_length=1)

    @field_validator("run_label")
    @classmethod
    def _valid_run_label(cls, v: str | None) -> str | None:
        if v is not None and not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}", v):
            raise ValueError("run_label: letters, digits, '_', '.', '-' only (max 64, no leading dot)")
        return v


class CheckResult(NamedTuple):
    """Outcome of a successful scope check."""

    resolved_ip: str  # Connect to this IP — prevents DNS rebinding
    scheme: str
    host: str  # Original hostname, for use in the Host header
    port: int


class ScopeViolationError(Exception):
    """Raised when a URL violates the scope configuration."""

    def __init__(self, reason: str, url: str = "") -> None:
        self.reason = reason
        self.url = url
        location = f" for {url!r}" if url else ""
        super().__init__(f"Scope violation{location}: {reason}")


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

Resolver = Callable[[str], list[str]]  # hostname → list[IP string]
_AnyIP = ipaddress.IPv4Address | ipaddress.IPv6Address
_AnyNet = ipaddress.IPv4Network | ipaddress.IPv6Network


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Matches user@host or user:pass@host in a netloc
_USERINFO_RE = re.compile(r"^[^@/]+@")

# Hostnames must contain only safe characters
_SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9.\-]+$")


def _parse_numeric_host(host: str) -> _AnyIP | None:
    """
    Try to interpret *host* as a numeric IP in any common encoding:

    - IPv6 literal in brackets: ``[::1]``
    - Bare hex integer: ``0x7f000001``
    - Bare decimal integer: ``2130706433``
    - Dotted notation with per-octet decimal / hex / octal: ``0177.0.0.1``
    - Standard dotted-decimal / plain IPv6 string

    Returns an IP address object, or ``None`` when *host* looks like a
    hostname rather than a numeric address.
    """
    # IPv6 literal: "[::1]"
    if host.startswith("[") and host.endswith("]"):
        try:
            return ipaddress.ip_address(host[1:-1])
        except ValueError:
            return None

    # Bare hex integer: 0x7f000001
    if re.match(r"^0[xX][0-9a-fA-F]+$", host):
        try:
            return ipaddress.ip_address(int(host, 16))
        except (ValueError, OverflowError):
            return None

    # Bare decimal integer: 2130706433
    if re.match(r"^\d+$", host):
        try:
            value = int(host)
            if 0 <= value <= 0xFFFF_FFFF:
                return ipaddress.ip_address(value)
        except (ValueError, OverflowError):
            pass
        return None

    # Dotted notation — may mix decimal / hex / octal per-octet: 0177.0.0.1
    parts = host.split(".")
    if len(parts) == 4:
        try:
            decoded: list[int] = []
            for part in parts:
                if re.match(r"^0[xX][0-9a-fA-F]+$", part):
                    decoded.append(int(part, 16))
                elif part.startswith("0") and len(part) > 1:
                    decoded.append(int(part, 8))
                else:
                    decoded.append(int(part, 10))
            if all(0 <= d <= 255 for d in decoded):
                return ipaddress.ip_address(".".join(str(d) for d in decoded))
        except (ValueError, OverflowError):
            return None

    # Standard dotted-decimal IPv4 or bare IPv6 string
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _default_resolver(host: str) -> list[str]:
    """Real DNS resolver used in production (not in tests)."""
    import socket

    results = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    return list({r[4][0] for r in results})


# ---------------------------------------------------------------------------
# ScopeGuard
# ---------------------------------------------------------------------------


class ScopeGuard:
    """
    Deny-by-default allowlist guard for HTTP URLs.

    *config* defines which hosts, IPs, ports and schemes are reachable.
    *resolver* is an injectable ``(hostname) → [ip_str, …]`` callable;
    production code uses the real DNS resolver; tests supply a fake to
    avoid real network calls.
    """

    def __init__(
        self, config: ScopeConfig, resolver: Resolver | None = None
    ) -> None:
        self._config = config
        self._resolver: Resolver = resolver or _default_resolver
        self._allowed_schemes: frozenset[str] = frozenset(
            s.lower() for s in config.allowed_schemes
        )
        self._allowed_networks: list[_AnyNet] = [
            ipaddress.ip_network(entry, strict=False) for entry in config.allowed_ips
        ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def config(self) -> ScopeConfig:
        """The (read-only) scope configuration this guard enforces."""
        return self._config

    def check(self, url: str) -> CheckResult:
        """
        Validate *url* against the scope configuration.

        Returns a :class:`CheckResult` whose ``resolved_ip`` the HTTP client
        must use directly (prevents DNS rebinding).  Raises
        :class:`ScopeViolationError` with a human-readable reason on any
        violation.
        """
        try:
            parsed = urlparse(url)
        except Exception as exc:
            raise ScopeViolationError(f"URL parse error: {exc}", url) from exc

        scheme, host, port = self._parse_and_validate_url(parsed, url)

        # Scheme allowlist check (after base http/https validation)
        if scheme not in self._allowed_schemes:
            raise ScopeViolationError(
                f"Scheme {scheme!r} is not in allowed_schemes", url
            )

        # Port check happens before DNS to fail fast and avoid unnecessary resolution
        if port not in self._config.allowed_ports:
            raise ScopeViolationError(f"Port {port} is not in allowed_ports", url)

        # Determine whether the host token is a literal IP or a hostname
        ip_obj = _parse_numeric_host(host)

        if ip_obj is not None:
            # Literal IP in the URL — must be explicitly listed in allowed_ips
            self._check_always_blocked(ip_obj, url)
            if not self._ip_in_allowed(ip_obj):
                raise ScopeViolationError(f"IP {ip_obj} is not in allowed_ips", url)
            return CheckResult(
                resolved_ip=str(ip_obj),
                scheme=scheme,
                host=str(ip_obj),
                port=port,
            )

        # Hostname — validate characters
        if not _SAFE_HOST_RE.match(host):
            raise ScopeViolationError(
                f"Hostname {host!r} contains invalid characters", url
            )

        # Resolve once, validate every returned IP
        try:
            raw_ips = self._resolver(host)
        except ScopeViolationError:
            raise
        except Exception as exc:
            raise ScopeViolationError(f"DNS resolution failed: {exc}", url) from exc

        if not raw_ips:
            raise ScopeViolationError("DNS returned no addresses", url)

        host_in_allowlist = host in self._config.allowed_hosts
        validated: list[_AnyIP] = []

        for raw in raw_ips:
            try:
                ip = ipaddress.ip_address(raw)
            except ValueError as exc:
                raise ScopeViolationError(
                    f"DNS returned malformed IP {raw!r}: {exc}", url
                ) from exc
            self._validate_resolved_ip(ip, host_in_allowlist, url)
            validated.append(ip)

        return CheckResult(
            resolved_ip=str(validated[0]),
            scheme=scheme,
            host=host,
            port=port,
        )

    # ------------------------------------------------------------------
    # Private — URL parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_and_validate_url(
        parsed: object, url: str
    ) -> tuple[str, str, int]:
        """Extract and validate scheme, host and port from a parsed URL."""
        scheme = (getattr(parsed, "scheme", "") or "").lower()
        if scheme not in ("http", "https"):
            raise ScopeViolationError(
                f"Scheme {scheme!r} is not http or https", url
            )

        netloc = getattr(parsed, "netloc", "") or ""
        if not netloc:
            raise ScopeViolationError("Missing or empty host", url)

        if _USERINFO_RE.match(netloc):
            raise ScopeViolationError("Userinfo (user@host) is not allowed", url)

        host, port = ScopeGuard._split_host_port(netloc, scheme, url)
        return scheme, host, port

    @staticmethod
    def _split_host_port(netloc: str, scheme: str, url: str) -> tuple[str, int]:
        """Extract host token and port from *netloc*."""
        default_port = 443 if scheme == "https" else 80

        if netloc.startswith("["):
            # IPv6 literal: [::1] or [::1]:8080
            end = netloc.find("]")
            if end == -1:
                raise ScopeViolationError("Malformed IPv6 bracket in netloc", url)
            host = netloc[: end + 1]  # e.g. "[::1]"
            tail = netloc[end + 1 :]
            if tail and tail[0] == ":":
                try:
                    return host, int(tail[1:])
                except ValueError:
                    raise ScopeViolationError(
                        f"Invalid port in {netloc!r}", url
                    ) from None
            return host, default_port

        if ":" in netloc:
            host, _, port_str = netloc.rpartition(":")
            try:
                return host, int(port_str)
            except ValueError:
                raise ScopeViolationError(
                    f"Invalid port in {netloc!r}", url
                ) from None

        return netloc, default_port

    # ------------------------------------------------------------------
    # Private — IP validation
    # ------------------------------------------------------------------

    def _check_always_blocked(self, ip: _AnyIP, url: str) -> None:
        """
        Raise :class:`ScopeViolationError` if *ip* is in an always-blocked
        range (link-local, etc.).  This check cannot be overridden by
        ``allowed_ips``.
        """
        if isinstance(ip, ipaddress.IPv6Address):
            mapped = ip.ipv4_mapped
            if mapped is not None:
                # Delegate: ::ffff:169.254.x.x → check as 169.254.x.x
                self._check_always_blocked(mapped, url)
                return
            for net in _ALWAYS_BLOCKED_V6:
                if ip in net:
                    raise ScopeViolationError(
                        f"IP {ip} is in an always-blocked range ({net})", url
                    )
        else:
            for net in _ALWAYS_BLOCKED_V4:
                if ip in net:
                    raise ScopeViolationError(
                        f"IP {ip} is in an always-blocked range ({net})", url
                    )

    def _is_restricted(self, ip: _AnyIP) -> bool:
        """
        Return ``True`` if *ip* is in a restricted (non-publicly-routable)
        range.  Uses an explicit list rather than ``ip.is_global`` to stay
        stable across Python versions.
        """
        if isinstance(ip, ipaddress.IPv6Address):
            mapped = ip.ipv4_mapped
            if mapped is not None:
                return self._is_restricted(mapped)
            return any(ip in net for net in _RESTRICTED_V6)
        return any(ip in net for net in _RESTRICTED_V4)

    def _ip_in_allowed(self, ip: _AnyIP) -> bool:
        """
        Return ``True`` if *ip* (or its IPv4-mapped equivalent) matches any
        entry in ``allowed_ips``.
        """
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            if self._ip_in_allowed(ip.ipv4_mapped):
                return True
        return any(ip in net for net in self._allowed_networks)

    def _validate_resolved_ip(
        self, ip: _AnyIP, host_in_allowlist: bool, url: str
    ) -> None:
        """
        Validate a DNS-resolved IP against the scope rules:

        1. Always-blocked ranges (link-local) → hard error, no override.
        2. Restricted ranges (loopback, private, …) → allowed only if
           the IP is explicitly in ``allowed_ips``.
        3. Public IP with host not in ``allowed_hosts`` and not in
           ``allowed_ips`` → blocked.
        """
        self._check_always_blocked(ip, url)

        in_allowed = self._ip_in_allowed(ip)

        if self._is_restricted(ip):
            if not in_allowed:
                raise ScopeViolationError(
                    f"Resolved IP {ip} is in a restricted range "
                    "and not explicitly listed in allowed_ips",
                    url,
                )
        else:
            # Public (non-restricted) IP: host must be authorised
            if not host_in_allowlist and not in_allowed:
                raise ScopeViolationError(
                    f"Resolved IP {ip}: host is not in allowed_hosts "
                    "and IP is not in allowed_ips",
                    url,
                )
