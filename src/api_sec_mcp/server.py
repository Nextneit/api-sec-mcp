"""
FastMCP server entrypoint for api-sec-mcp.

Registers security tools and initializes the security gateway layers.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from fastmcp import FastMCP

from api_sec_mcp.egress.client import EgressClient
from api_sec_mcp.egress.scope_guard import ScopeConfig, ScopeGuard
from api_sec_mcp.models import HeadersReport, JwtReport
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
    return EgressClient(
        scope_guard=guard,
        timeout=float(guard.config.request_timeout_seconds),
        max_response_bytes=guard.config.max_response_bytes,
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
    report: HeadersReport = await inspect_security_headers(url=url, client=client)
    return report.model_dump()


@mcp.tool()
def audit_json_web_token(token: str) -> dict:
    """
    Audit a JSON Web Token (JWT) for signature bypasses (alg=none),
    weak dictionary HMAC keys, missing/expired expiration, and sensitive claims.
    Returns a typed, bounded security report.
    """
    report: JwtReport = audit_jwt(token=token)
    return report.model_dump()


def main() -> None:
    """CLI entrypoint."""
    mcp.run()


if __name__ == "__main__":
    main()
