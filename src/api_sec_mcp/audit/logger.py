"""
Append-only, hash-chained JSONL audit log (SPEC-002).

- Metadata only: never headers, bodies, query values, credentials or JWT contents.
- Audit-or-deny: any write failure raises ``AuditError``; callers must not proceed.
- Each line carries the SHA-256 of the previous line (tamper evidence, not a defence
  against a compromised host).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from contextvars import ContextVar
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, NamedTuple
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator

from api_sec_mcp.models import safe_label, sanitize_evidence

GENESIS_HASH = "0" * 64
_MAX_PATH_CHARS = 256

# Set by the MCP tool wrapper so egress events can be attributed to a tool.
current_tool: ContextVar[str | None] = ContextVar("current_tool", default=None)


class AuditError(Exception):
    """The audit trail could not be written; the guarded operation must not proceed."""


class EventType(StrEnum):
    TOOL_CALL = "TOOL_CALL"
    EGRESS_BLOCKED = "EGRESS_BLOCKED"
    EGRESS_ALLOWED = "EGRESS_ALLOWED"
    EGRESS_COMPLETED = "EGRESS_COMPLETED"
    EGRESS_ERROR = "EGRESS_ERROR"


def redact_url(url: str) -> str:
    """``scheme://host[:port]/path`` only: no userinfo, query or fragment; bounded & sanitized."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        return "invalid-url"
    if ":" in host:
        host = f"[{host}]"
    netloc = f"{host}:{port}" if port else host
    path = "".join(c for c in parsed.path if c.isprintable() and c not in "<>\"'`\\")
    scheme = safe_label(parsed.scheme, 16) if parsed.scheme else ""
    return f"{scheme}://{safe_label_host(netloc)}{path[:_MAX_PATH_CHARS]}"


def safe_label_host(netloc: str) -> str:
    return "".join(c for c in netloc[:261] if c.isalnum() or c in ".-:[]_")


class AuditEvent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    seq: int
    ts: str
    prev: str
    event: EventType
    tool: str | None = None
    method: str | None = None
    url: str | None = None
    host: str | None = None
    resolved_ip: str | None = None
    status_code: int | None = None
    bytes_read: int | None = None
    duration_ms: int | None = None
    reason: str | None = Field(default=None, max_length=128)
    findings: int | None = None

    @field_validator("url", mode="before")
    @classmethod
    def _redact(cls, v: str | None) -> str | None:
        return redact_url(v) if v is not None else None

    @field_validator("reason", mode="before")
    @classmethod
    def _sanitize_reason(cls, v: str | None) -> str | None:
        return sanitize_evidence(v)

    @field_validator("tool", "method", "host", "resolved_ip", mode="before")
    @classmethod
    def _sanitize_labels(cls, v: str | None) -> str | None:
        return safe_label(v, 253) if v is not None else None


class VerifyResult(NamedTuple):
    ok: bool
    bad_seq: int | None
    lines: int


def _digest(line: str) -> str:
    return hashlib.sha256(line.encode()).hexdigest()


def _dump(event: AuditEvent) -> str:
    return json.dumps(event.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


class AuditLog:
    """Serialized, append-only writer. Resumes seq/prev from an existing file."""

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._lock = asyncio.Lock()
        self._seq = 0
        self._prev = GENESIS_HASH
        try:
            if self._path.exists():
                last = None
                with open(self._path, encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            last = line.rstrip("\n")
                if last:
                    self._seq = json.loads(last)["seq"] + 1
                    self._prev = _digest(last)
            self._fd = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        except (OSError, ValueError, KeyError) as exc:
            raise AuditError(f"Cannot open audit log: {type(exc).__name__}") from exc

    async def record(self, event: EventType, **fields: Any) -> None:  # noqa: ANN401
        async with self._lock:
            try:
                fields.setdefault("tool", current_tool.get())
                entry = AuditEvent(
                    seq=self._seq,
                    ts=datetime.now(UTC).isoformat(timespec="milliseconds"),
                    prev=self._prev,
                    event=event,
                    **fields,
                )
                line = _dump(entry)
                data = (line + "\n").encode()
                while data:
                    data = data[os.write(self._fd, data) :]
            except Exception as exc:
                raise AuditError(f"Audit write failed: {type(exc).__name__}") from exc
            self._seq += 1
            self._prev = _digest(line)


def verify_chain(path: Path | str) -> VerifyResult:
    """Check seq continuity and hash links. Tail truncation is undetectable (documented)."""
    prev = GENESIS_HASH
    n = 0
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if not line:
                continue
            try:
                data = json.loads(line)
                ok = data["seq"] == n and data["prev"] == prev
            except (ValueError, KeyError, TypeError):
                ok = False
            if not ok:
                return VerifyResult(False, n, n)
            prev = _digest(line)
            n += 1
    return VerifyResult(True, None, n)


def main(argv: list[str] | None = None) -> int:
    """CLI: ``api-sec-verify [path]`` — exit 0 if the chain is intact, 1 if not, 2 on I/O error."""
    import sys

    args = sys.argv[1:] if argv is None else argv
    path = Path(args[0]) if args else Path("audit.jsonl")
    if not path.is_file():
        print(f"Audit log not found: {path}. It is created when the server handles its first call.")
        return 2
    result = verify_chain(path)
    if result.ok:
        print(f"OK: {result.lines} events, chain intact ({path})")
        return 0
    print(f"TAMPERED: chain broken at seq {result.bad_seq} ({path})")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
