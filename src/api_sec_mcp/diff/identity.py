"""Finding identity and target normalization (SPEC-008 R1)."""

from __future__ import annotations

from typing import NamedTuple
from urllib.parse import urlparse

_DEFAULT_PORTS = {"http": 80, "https": 443}
_MAX_PATH = 256
_HOST_OK = set("abcdefghijklmnopqrstuvwxyz0123456789.-:[]_")


class FindingKey(NamedTuple):
    """Identity of a finding. Severity, description and evidence are deliberately excluded."""

    tool: str
    target: str
    rule: str
    location: str


def normalize_target(url: str) -> str:
    """scheme://host[:port]/path — lowercase, no userinfo/query/fragment, default port dropped."""
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        return "invalid-url"
    scheme = parsed.scheme.lower()
    host = "".join(c for c in (parsed.hostname or "").lower() if c in _HOST_OK)
    if ":" in host:
        host = f"[{host}]"
    netloc = host if port in (None, _DEFAULT_PORTS.get(scheme)) else f"{host}:{port}"
    path = "".join(c for c in (parsed.path or "/") if " " <= c <= "~" and c not in "<>\"'`\\")
    return f"{scheme}://{netloc}{path[:_MAX_PATH]}"
