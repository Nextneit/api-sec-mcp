"""
FastMCP server entrypoint for api-sec-mcp.

Registers security tools and initializes the security gateway layers.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from fastmcp import FastMCP

from api_sec_mcp.audit.logger import AuditLog, EventType, current_tool
from api_sec_mcp.egress.client import EgressClient
from api_sec_mcp.egress.rate_limit import RateLimiter
from api_sec_mcp.egress.scope_guard import ScopeConfig, ScopeGuard
from api_sec_mcp.guards.sanitizer import apply_guard
from api_sec_mcp.models import CorsReport, HeadersReport, JwtReport
from api_sec_mcp.tools.cors import inspect_cors
from api_sec_mcp.tools.headers import inspect_security_headers
from api_sec_mcp.tools.jwt_audit import audit_jwt

# Initialize FastMCP Server
mcp = FastMCP("api-sec-mcp")

_CLIENT: EgressClient | None = None


def load_scope_guard(config_path: Path | str | None = None) -> ScopeGuard:
    """Load the engagement scope. Fail-closed: no fallback to the example file."""
    path = Path(config_path) if config_path else Path("scope.yaml")
    if not path.is_file():
        raise FileNotFoundError(
            f"Scope file {path} not found. Copy scope.example.yaml to scope.yaml "
            "and edit it to authorize your engagement targets."
        )

    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    return ScopeGuard(ScopeConfig(**data))


def build_egress_client(guard: ScopeGuard) -> EgressClient:
    """Build the egress client honoring limits declared in the scope config."""
    config = guard.config
    audit = AuditLog(config.audit_log_path)
    # The budget survives restarts: already-spent requests are recovered from the audit log.
    limiter = RateLimiter(config, used=audit.count(EventType.EGRESS_ALLOWED))
    return EgressClient(
        scope_guard=guard,
        timeout=float(config.request_timeout_seconds),
        max_response_bytes=config.max_response_bytes,
        audit=audit,
        limiter=limiter,
    )


def get_egress_client() -> EgressClient:
    """Singleton getter for guarded EgressClient."""
    global _CLIENT
    if _CLIENT is None:
        _CLIENT = build_egress_client(load_scope_guard())
    return _CLIENT


@mcp.tool()
async def audit_security_headers(url: str) -> dict:
    """
    Inspect HTTP security headers for an authorized target URL.
    Returns a typed, bounded security report.
    """
    client = get_egress_client()
    token = current_tool.set("audit_security_headers")
    try:
        report: HeadersReport = await inspect_security_headers(url=url, client=client)
        return await _finish(client, report.model_dump(), url=url)
    finally:
        current_tool.reset(token)


@mcp.tool()
async def audit_cors(url: str) -> dict:
    """
    Audit CORS configuration of an authorized target URL using a fixed set of
    4 origin probes (arbitrary, null, look-alike suffix, preflight).
    Returns a typed, bounded security report.
    """
    client = get_egress_client()
    token = current_tool.set("audit_cors")
    try:
        report: CorsReport = await inspect_cors(url=url, client=client)
        return await _finish(client, report.model_dump(), url=url)
    finally:
        current_tool.reset(token)


@mcp.tool()
async def audit_json_web_token(token: str) -> dict:
    """
    Audit a JSON Web Token (JWT) offline for signature bypasses (alg=none), weak HMAC keys,
    header key-injection vectors (jku/x5u/jwk/x5c/kid/crit), missing audience/issuer,
    time-claim problems and sensitive claim names.
    Returns a typed, bounded security report.
    """
    client = get_egress_client()
    ctx = current_tool.set("audit_json_web_token")
    try:
        report: JwtReport = audit_jwt(token=token)
        # Never log the token or its claims: only its length.
        return await _finish(client, report.model_dump(), bytes_read=len(token))
    finally:
        current_tool.reset(ctx)


async def _finish(client: EgressClient, report: dict, **fields: Any) -> dict:  # noqa: ANN401
    """Single choke point: output guard, then audit of the flags and of the tool call."""
    result = apply_guard(report)
    if client.audit is not None:
        if result.flags:
            ids = sorted({p.value for f in result.flags for p in f.patterns})
            await client.audit.record(EventType.OUTPUT_FLAGGED, reason=",".join(ids))
        await client.audit.record(
            EventType.TOOL_CALL, findings=len(result.report.get("findings", [])), **fields
        )
    return result.report


def main() -> None:
    """CLI entrypoint."""
    mcp.run()


if __name__ == "__main__":
    main()
