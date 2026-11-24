"""
FastMCP server entrypoint for api-sec-mcp.

Registers security tools and initializes the security gateway layers.
"""

from __future__ import annotations

import os
from pathlib import Path
import sys
import yaml

from fastmcp import FastMCP

from api_sec_mcp.egress.client import EgressClient
from api_sec_mcp.egress.scope_guard import ScopeConfig, ScopeGuard
from api_sec_mcp.models import HeadersReport
from api_sec_mcp.tools.headers import inspect_security_headers

# Initialize FastMCP Server
mcp = FastMCP("api-sec-mcp")

_CLIENT: EgressClient | None = None


def load_scope_guard(config_path: Path | str | None = None) -> ScopeGuard:
    """Load scope.yaml or fallback to scope.example.yaml."""
    path = Path(config_path) if config_path else Path("scope.yaml")
    if not path.is_file():
        example_path = Path("scope.example.yaml")
        if example_path.is_file():
            path = example_path
        else:
            raise FileNotFoundError(f"Neither {path} nor scope.example.yaml could be found.")

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    config = ScopeConfig(**data)
    return ScopeGuard(config)


def get_egress_client() -> EgressClient:
    """Singleton getter for guarded EgressClient."""
    global _CLIENT
    if _CLIENT is None:
        guard = load_scope_guard()
        _CLIENT = EgressClient(scope_guard=guard)
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


def main() -> None:
    """CLI entrypoint."""
    mcp.run()


if __name__ == "__main__":
    main()
