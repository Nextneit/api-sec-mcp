"""
Safe egress HTTP client.

Principles enforced:
1. Always validate target URL with ScopeGuard before sending.
2. Connect directly to the validated IP to prevent DNS rebinding attacks,
   while preserving the original host header and SNI hostname.
3. Strictly disable following redirects (follow_redirects=False).
4. Enforce timeout and max response size limits (Content-Length, streaming cutoff, and decompressed bytes).
5. Raw response body never leaves egress layer unparsed.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import urlparse, urlunparse

import httpx

from api_sec_mcp.egress.scope_guard import CheckResult, ScopeGuard, ScopeViolationError


class EgressError(Exception):
    """Base error for egress operations."""


class ResponseTooLargeError(EgressError):
    """Raised when server response exceeds the configured maximum bytes."""


class EgressTimeoutError(EgressError):
    """Raised when an egress request times out."""


class EgressConnectionError(EgressError):
    """Raised when connection fails at the transport layer."""


@dataclass(frozen=True)
class EgressResponse:
    """
    Internal bounded response representation.
    Only factual metadata and controlled content are held.
    """

    status_code: int
    headers: Mapping[str, str]
    content: bytes
    url: str
    multi_headers: Mapping[str, list[str]] = field(default_factory=dict)


class EgressClient:
    """
    Guarded HTTP client.

    Every request is strictly validated against ScopeGuard and performed
    against the resolved IP address to prevent DNS rebinding, preserving
    SNI and Host headers.
    """

    def __init__(
        self,
        scope_guard: ScopeGuard,
        timeout: float = 10.0,
        max_response_bytes: int = 1_048_576,
        transport: httpx.AsyncBaseTransport | None = None,
        verify: bool = True,
    ) -> None:
        self._guard = scope_guard
        self._timeout = timeout
        self._max_response_bytes = max_response_bytes
        self._transport = transport
        self.verify = verify

    async def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
    ) -> EgressResponse:
        """Perform a guarded GET request."""
        return await self.request("GET", url, headers=headers)

    async def head(
        self,
        url: str,
        headers: dict[str, str] | None = None,
    ) -> EgressResponse:
        """Perform a guarded HEAD request."""
        return await self.request("HEAD", url, headers=headers)

    async def options(
        self,
        url: str,
        headers: dict[str, str] | None = None,
    ) -> EgressResponse:
        """Perform a guarded OPTIONS request."""
        return await self.request("OPTIONS", url, headers=headers)

    async def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
    ) -> EgressResponse:
        """
        Validate URL with ScopeGuard, rewrite URL to target resolved IP,
        set explicit Host header and SNI extension, and execute without
        following redirects.
        """
        check_result: CheckResult = self._guard.check(url)

        req_headers = dict(headers or {})
        # Ensure Host header reflects the original host (and non-standard port if present)
        if "host" not in {k.lower(): k for k in req_headers}:
            if (check_result.scheme == "https" and check_result.port != 443) or (
                check_result.scheme == "http" and check_result.port != 80
            ):
                req_headers["Host"] = f"{check_result.host}:{check_result.port}"
            else:
                req_headers["Host"] = check_result.host

        # Build connection URL targeting resolved_ip directly
        parsed = urlparse(url)
        ip_target = (
            f"[{check_result.resolved_ip}]"
            if ":" in check_result.resolved_ip and not check_result.resolved_ip.startswith("[")
            else check_result.resolved_ip
        )
        netloc = f"{ip_target}:{check_result.port}" if check_result.port else ip_target

        ip_url = urlunparse(
            (
                check_result.scheme,
                netloc,
                parsed.path or "/",
                parsed.params,
                parsed.query,
                parsed.fragment,
            )
        )

        extensions: dict[str, Any] = {"sni_hostname": check_result.host}

        try:
            async with httpx.AsyncClient(
                transport=self._transport,
                timeout=self._timeout,
                follow_redirects=False,
                verify=self.verify,
            ) as client:
                req = client.build_request(
                    method=method,
                    url=ip_url,
                    headers=req_headers,
                    content=content,
                    extensions=extensions,
                )

                response = await client.send(req, stream=True)
                try:
                    # Check Content-Length upfront before reading body
                    content_length = response.headers.get("content-length")
                    if content_length is not None:
                        try:
                            if int(content_length) > self._max_response_bytes:
                                raise ResponseTooLargeError(
                                    f"Response Content-Length ({content_length} bytes) "
                                    f"exceeds maximum allowed size of {self._max_response_bytes} bytes"
                                )
                        except ValueError:
                            pass

                    # aiter_bytes() automatically decompresses if Content-Encoding is set (e.g. gzip)
                    # Enforce max response size on decompressed streaming chunks
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > self._max_response_bytes:
                            raise ResponseTooLargeError(
                                f"Response exceeded maximum allowed size of {self._max_response_bytes} bytes"
                            )

                    # Build normalized headers dict and multi-headers dict
                    normalized_headers: dict[str, str] = {}
                    multi_headers: defaultdict[str, list[str]] = defaultdict(list)

                    for k, v in response.headers.multi_items():
                        lower_k = k.lower()
                        normalized_headers[lower_k] = v
                        multi_headers[lower_k].append(v)

                    return EgressResponse(
                        status_code=response.status_code,
                        headers=normalized_headers,
                        content=bytes(body),
                        url=url,
                        multi_headers=dict(multi_headers),
                    )
                finally:
                    await response.aclose()
        except httpx.TimeoutException as exc:
            raise EgressTimeoutError(f"Request to {url} timed out: {type(exc).__name__}") from exc
        except httpx.ConnectError as exc:
            raise EgressConnectionError(f"Connection failed for {url}: {type(exc).__name__}") from exc
        except (ResponseTooLargeError, ScopeViolationError, EgressError):
            raise
        except Exception as exc:
            raise EgressError(f"Egress request failed for {url}: {type(exc).__name__}") from exc
