"""Tests derived from specs/002-audit-log.md (R1-R8)."""

import asyncio
import json
import os
import stat

import httpx
import pytest

from api_sec_mcp import server
from api_sec_mcp.audit.logger import (
    AuditError,
    AuditEvent,
    AuditLog,
    EventType,
    current_tool,
    redact_url,
    verify_chain,
)
from api_sec_mcp.egress.client import EgressClient, EgressError, ResponseTooLargeError
from api_sec_mcp.egress.scope_guard import ScopeConfig, ScopeGuard, ScopeViolationError


def read_events(path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def make_guard(**kw) -> ScopeGuard:
    cfg = ScopeConfig(
        allowed_hosts=["api.example.com"], allowed_ips=["203.0.113.10"],
        allowed_ports=[443], allowed_schemes=["https"], **kw,
    )
    return ScopeGuard(cfg, resolver=lambda h: ["203.0.113.10"])


# ---------------- R1 ----------------
async def test_r1_concurrent_writes_are_atomic_and_ordered(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    await asyncio.gather(*(log.record(EventType.TOOL_CALL, tool=f"t{i}") for i in range(100)))
    events = read_events(tmp_path / "a.jsonl")
    assert [e["seq"] for e in events] == list(range(100))


async def test_r1_file_mode_0600(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    await log.record(EventType.TOOL_CALL)
    assert stat.S_IMODE(os.stat(tmp_path / "a.jsonl").st_mode) == 0o600


# ---------------- R2 ----------------
def test_r2_unknown_fields_rejected():
    with pytest.raises(ValueError):
        AuditEvent(seq=0, ts="x", prev="0" * 64, event=EventType.TOOL_CALL, bogus=1)


async def test_r2_reason_bounded_and_sanitized(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    await log.record(EventType.EGRESS_BLOCKED, reason="bad\n\x00<script>" + "A" * 500)
    (e,) = read_events(tmp_path / "a.jsonl")
    assert len(e["reason"]) <= 128 and "\n" not in e["reason"] and "<" not in e["reason"]


async def test_r2_tool_from_contextvar(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    token = current_tool.set("my_tool")
    try:
        await log.record(EventType.TOOL_CALL)
    finally:
        current_tool.reset(token)
    assert read_events(tmp_path / "a.jsonl")[0]["tool"] == "my_tool"


# ---------------- R3 ----------------
def test_r3_url_redaction():
    assert redact_url("https://u:p@api.example.com/x?token=abc#f") == "https://api.example.com/x"
    assert redact_url("http://[::1]:8080/a?b=c") == "http://[::1]:8080/a"
    assert len(redact_url("https://h.com/" + "a" * 1000)) <= len("https://h.com") + 257


async def test_r3_event_url_is_redacted(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    await log.record(EventType.TOOL_CALL, url="https://h.com/p?secret=1")
    assert "secret" not in (tmp_path / "a.jsonl").read_text()


# ---------------- R4 / R5 ----------------
def ok_transport():
    return httpx.MockTransport(lambda r: httpx.Response(200, content=b"hello"))


async def test_r4_blocked_event(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    client = EgressClient(make_guard(), transport=ok_transport(), audit=log)
    with pytest.raises(ScopeViolationError):
        await client.get("https://169.254.169.254/x?k=v")
    events = read_events(tmp_path / "a.jsonl")
    assert [e["event"] for e in events] == ["EGRESS_BLOCKED"]
    assert events[0]["url"] == "https://169.254.169.254/x" and events[0]["reason"]


async def test_r4_success_events(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    client = EgressClient(make_guard(), transport=ok_transport(), audit=log)
    await client.get("https://api.example.com/x")
    events = read_events(tmp_path / "a.jsonl")
    assert [e["event"] for e in events] == ["EGRESS_ALLOWED", "EGRESS_COMPLETED"]
    assert events[0]["resolved_ip"] == "203.0.113.10" and events[0]["host"] == "api.example.com"
    assert events[1]["status_code"] == 200 and events[1]["bytes_read"] == 5
    assert events[1]["duration_ms"] >= 0


@pytest.mark.parametrize(
    ("handler", "exc", "reason"),
    [
        (lambda r: (_ for _ in ()).throw(httpx.ConnectTimeout("t")), EgressError, "EgressTimeoutError"),
        (lambda r: (_ for _ in ()).throw(httpx.ConnectError("c")), EgressError, "EgressConnectionError"),
        (lambda r: httpx.Response(200, content=b"x" * 50), ResponseTooLargeError, "ResponseTooLargeError"),
    ],
)
async def test_r4_error_events(tmp_path, handler, exc, reason):
    log = AuditLog(tmp_path / "a.jsonl")
    client = EgressClient(
        make_guard(), transport=httpx.MockTransport(handler), audit=log, max_response_bytes=10
    )
    with pytest.raises(exc):
        await client.get("https://api.example.com/x")
    events = read_events(tmp_path / "a.jsonl")
    assert [e["event"] for e in events] == ["EGRESS_ALLOWED", "EGRESS_ERROR"]
    assert events[1]["reason"] == reason


async def test_r5_audit_failure_means_no_network_io():
    calls = []

    class BrokenLog:
        async def record(self, *a, **k):
            raise AuditError("disk full")

    transport = httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(200))
    client = EgressClient(make_guard(), transport=transport, audit=BrokenLog())
    with pytest.raises(AuditError):
        await client.get("https://api.example.com/x")
    assert calls == []


async def test_r5_unwritable_path_raises_audit_error(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    os.close(log._fd)  # simulate a broken descriptor
    with pytest.raises(AuditError):
        await log.record(EventType.TOOL_CALL)


# ---------------- R6 ----------------
async def test_r6_tool_events_and_no_token_leak(tmp_path, monkeypatch):
    import jwt as pyjwt

    path = tmp_path / "audit.jsonl"
    guard = make_guard(audit_log_path=str(path))
    client = server.build_egress_client(guard)
    monkeypatch.setattr(server, "_CLIENT", client)

    token = pyjwt.encode({"sub": "DISTINCTIVE_SUBJECT_42"}, "secret", algorithm="HS256")
    await server.audit_json_web_token(token)

    raw = path.read_text()
    assert "DISTINCTIVE_SUBJECT_42" not in raw
    for i in range(0, len(token) - 12, 6):
        assert token[i : i + 12] not in raw
    (e,) = read_events(path)
    assert e["event"] == "TOOL_CALL" and e["tool"] == "audit_json_web_token"
    assert e["bytes_read"] == len(token) and e["findings"] >= 1


# ---------------- R7 ----------------
async def _make_log(path, n=5):
    log = AuditLog(path)
    for i in range(n):
        await log.record(EventType.TOOL_CALL, tool=f"t{i}")
    return log


async def test_r7_valid_chain(tmp_path):
    p = tmp_path / "a.jsonl"
    await _make_log(p)
    r = verify_chain(p)
    assert r.ok and r.lines == 5 and r.bad_seq is None


async def test_r7_mutation_detected(tmp_path):
    p = tmp_path / "a.jsonl"
    await _make_log(p)
    lines = p.read_text().splitlines()
    lines[2] = lines[2].replace("t2", "tX")
    p.write_text("\n".join(lines) + "\n")
    r = verify_chain(p)
    assert not r.ok and r.bad_seq == 3  # first line whose prev no longer matches


async def test_r7_deletion_and_reorder_detected(tmp_path):
    p = tmp_path / "a.jsonl"
    await _make_log(p)
    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines[:1] + lines[2:]) + "\n")
    assert not verify_chain(p).ok
    p.write_text("\n".join([lines[0], lines[2], lines[1]] + lines[3:]) + "\n")
    assert not verify_chain(p).ok


async def test_r7_resume_after_restart(tmp_path):
    p = tmp_path / "a.jsonl"
    await _make_log(p, 3)
    log2 = AuditLog(p)
    await log2.record(EventType.TOOL_CALL, tool="after")
    r = verify_chain(p)
    assert r.ok and r.lines == 4


# ---------------- R8 ----------------
def test_r8_config_default_and_wiring(tmp_path):
    assert ScopeConfig().audit_log_path == "audit.jsonl"
    client = server.build_egress_client(make_guard(audit_log_path=str(tmp_path / "x.jsonl")))
    assert client.audit is not None
    assert (tmp_path / "x.jsonl").exists()
    assert "audit.jsonl" in open(".gitignore").read()
