"""Tests derived from specs/004-rate-limit.md (R1-R7)."""

import asyncio
import json

import httpx
import pytest
from pydantic import ValidationError

from api_sec_mcp import server
from api_sec_mcp.audit.logger import AuditError, AuditLog, EventType
from api_sec_mcp.egress.client import EgressClient, EgressError, ResponseTooLargeError
from api_sec_mcp.egress.rate_limit import LimitKind, RateLimiter, RateLimitExceededError
from api_sec_mcp.egress.scope_guard import ScopeConfig, ScopeGuard, ScopeViolationError
from api_sec_mcp.tools.cors import inspect_cors

URL = "https://api.example.com/x"


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def cfg(**kw) -> ScopeConfig:
    return ScopeConfig(
        allowed_hosts=["api.example.com"], allowed_ips=["203.0.113.10"],
        allowed_ports=[443], allowed_schemes=["https"], **kw,
    )


def make_client(config, handler=None, audit=None, used=0, clock=None):
    calls: list[httpx.Request] = []

    def default(req):
        return httpx.Response(200, content=b"ok")

    async def wrapped(req):
        calls.append(req)
        h = handler or default
        r = h(req)
        return await r if asyncio.iscoroutine(r) else r

    guard = ScopeGuard(config, resolver=lambda h: ["203.0.113.10"])
    limiter = RateLimiter(config, clock=clock or Clock(), used=used)
    client = EgressClient(
        guard, transport=httpx.MockTransport(wrapped), audit=audit, limiter=limiter,
        max_response_bytes=10,
    )
    return client, limiter, calls


def events(path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


# ---------------- R1 ----------------
def test_r1_defaults():
    c = ScopeConfig()
    assert (c.max_requests_total, c.max_requests_per_host_per_minute, c.max_concurrent_requests) == (
        1000, 60, 4)


@pytest.mark.parametrize("field", ["max_requests_total", "max_requests_per_host_per_minute",
                                   "max_concurrent_requests"])
@pytest.mark.parametrize("bad", [0, -1, "abc", 1.5])
def test_r1_invalid_values_rejected(field, bad):
    with pytest.raises(ValidationError):
        ScopeConfig(**{field: bad})


def test_r1_example_documents_limits():
    text = open("scope.example.yaml").read()
    for f in ("max_requests_total", "max_requests_per_host_per_minute", "max_concurrent_requests"):
        assert f in text
    assert server.load_scope_guard("scope.example.yaml").config.max_requests_total == 1000


# ---------------- R2 ----------------
def test_r2_host_window_sliding():
    clock = Clock()
    lim = RateLimiter(cfg(max_requests_per_host_per_minute=60, max_concurrent_requests=100,
                          max_requests_total=1000), clock=clock)
    for _ in range(60):
        lim.acquire("a.com").release()
        clock.t += 0.5  # 30 s total
    with pytest.raises(RateLimitExceededError) as ei:
        lim.acquire("a.com")
    assert ei.value.kind == LimitKind.HOST_RATE and ei.value.retry_after == 30
    clock.t += 30  # oldest request now 60 s old
    lim.acquire("a.com").release()


def test_r2_hosts_are_independent_and_failures_consume_nothing():
    lim = RateLimiter(cfg(max_requests_per_host_per_minute=1, max_concurrent_requests=10))
    lim.acquire("a.com").release()
    lim.acquire("B.com").release()
    used = lim.used
    with pytest.raises(RateLimitExceededError):
        lim.acquire("A.COM")
    assert lim.used == used and lim.inflight == 0


def test_r2_check_order_total_then_concurrency_then_host():
    lim = RateLimiter(cfg(max_requests_total=1, max_concurrent_requests=1,
                          max_requests_per_host_per_minute=1))
    lease = lim.acquire("a.com")
    with pytest.raises(RateLimitExceededError) as ei:
        lim.acquire("a.com")
    assert ei.value.kind == LimitKind.TOTAL_BUDGET and ei.value.retry_after is None
    lease.release()

    lim = RateLimiter(cfg(max_requests_total=10, max_concurrent_requests=1,
                          max_requests_per_host_per_minute=1))
    lim.acquire("a.com")
    with pytest.raises(RateLimitExceededError) as ei:
        lim.acquire("a.com")
    assert ei.value.kind == LimitKind.CONCURRENCY


def test_r2_lease_release_idempotent():
    lim = RateLimiter(cfg(max_concurrent_requests=1))
    lease = lim.acquire("a.com")
    lease.release()
    lease.release()
    assert lim.inflight == 0


# ---------------- R3 ----------------
async def test_r3_audit_log_counts_events(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    for _ in range(3):
        await log.record(EventType.EGRESS_ALLOWED)
    await log.record(EventType.TOOL_CALL)
    assert log.count(EventType.EGRESS_ALLOWED) == 3
    assert AuditLog(p).count(EventType.EGRESS_ALLOWED) == 3
    assert AuditLog(tmp_path / "new.jsonl").count(EventType.EGRESS_ALLOWED) == 0


async def test_r3_budget_survives_restart(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    for _ in range(7):
        await log.record(EventType.EGRESS_ALLOWED)
    config = cfg(audit_log_path=str(p), max_requests_total=10)
    client = server.build_egress_client(ScopeGuard(config, resolver=lambda h: ["203.0.113.10"]))
    for _ in range(3):
        client.limiter.acquire("a.com").release()
    with pytest.raises(RateLimitExceededError) as ei:
        client.limiter.acquire("a.com")
    assert ei.value.kind == LimitKind.TOTAL_BUDGET


def test_r3_fresh_log_full_budget(tmp_path):
    config = cfg(audit_log_path=str(tmp_path / "n.jsonl"), max_requests_total=5)
    client = server.build_egress_client(ScopeGuard(config, resolver=lambda h: ["203.0.113.10"]))
    assert client.limiter.used == 0


# ---------------- R4 ----------------
async def _wait_for(pred, timeout=2.0):
    end = asyncio.get_event_loop().time() + timeout
    while not pred():
        assert asyncio.get_event_loop().time() < end, "timeout"
        await asyncio.sleep(0.01)


async def test_r4_concurrency_cap_and_release_on_success():
    gate = asyncio.Event()

    async def handler(req):
        await gate.wait()
        return httpx.Response(200)

    client, lim, calls = make_client(cfg(max_concurrent_requests=2), handler)
    t1 = asyncio.create_task(client.get(URL))
    t2 = asyncio.create_task(client.get(URL))
    await _wait_for(lambda: len(calls) == 2)
    with pytest.raises(RateLimitExceededError) as ei:
        await client.get(URL)
    assert ei.value.kind == LimitKind.CONCURRENCY
    gate.set()
    await asyncio.gather(t1, t2)
    assert lim.inflight == 0
    await client.get(URL)


async def test_r4_release_on_error_and_cancellation():
    def boom(req):
        raise httpx.ConnectError("x")

    client, lim, _ = make_client(cfg(max_concurrent_requests=1), boom)
    with pytest.raises(EgressError):
        await client.get(URL)
    assert lim.inflight == 0

    gate = asyncio.Event()

    async def slow(req):
        await gate.wait()
        return httpx.Response(200)

    client, lim, calls = make_client(cfg(max_concurrent_requests=1), slow)
    t = asyncio.create_task(client.get(URL))
    await _wait_for(lambda: len(calls) == 1)
    t.cancel()
    with pytest.raises(asyncio.CancelledError):
        await t
    assert lim.inflight == 0


# ---------------- R5 ----------------
async def test_r5_scope_violation_consumes_nothing():
    client, lim, _ = make_client(cfg())
    with pytest.raises(ScopeViolationError):
        await client.get("https://169.254.169.254/x")
    assert lim.used == 0


async def test_r5_errors_consume_budget():
    def boom(req):
        raise httpx.ConnectTimeout("t")

    client, lim, _ = make_client(cfg(), boom)
    with pytest.raises(EgressError):
        await client.get(URL)
    client2, lim2, _ = make_client(cfg(), lambda r: httpx.Response(200, content=b"x" * 50))
    with pytest.raises(ResponseTooLargeError):
        await client2.get(URL)
    assert lim.used == 1 and lim2.used == 1


async def test_r5_rate_limited_event_and_no_transport_call(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    client, _, calls = make_client(cfg(max_requests_total=1), audit=log)
    await client.get(URL)
    with pytest.raises(RateLimitExceededError):
        await client.get(URL)
    ev = events(tmp_path / "a.jsonl")
    assert [e["event"] for e in ev] == [
        "EGRESS_ALLOWED", "EGRESS_COMPLETED", "EGRESS_RATE_LIMITED"]
    assert ev[2]["reason"] == "TOTAL_BUDGET" and ev[2]["host"] == "api.example.com"
    assert len(calls) == 1


async def test_r5_audit_failure_refunds_lease():
    class Broken:
        async def record(self, *a, **k):
            raise AuditError("x")

    client, lim, calls = make_client(cfg(), audit=Broken())
    with pytest.raises(AuditError):
        await client.get(URL)
    assert lim.used == 0 and lim.inflight == 0 and calls == []


# ---------------- R6 ----------------
async def test_r6_cors_all_or_nothing(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    client, lim, calls = make_client(cfg(max_requests_total=3), audit=log)
    with pytest.raises(RateLimitExceededError) as ei:
        await inspect_cors(URL, client)
    assert ei.value.kind == LimitKind.TOTAL_BUDGET and calls == []
    assert [e["event"] for e in events(tmp_path / "a.jsonl")] == ["EGRESS_RATE_LIMITED"]


async def test_r6_cors_consumes_exactly_probes():
    client, lim, calls = make_client(cfg(max_requests_total=4))
    await inspect_cors(URL, client)
    assert lim.used == 4 and len(calls) == 4
    with pytest.raises(RateLimitExceededError):
        await inspect_cors(URL, client)


async def test_r6_ensure_capacity_without_limiter_is_noop():
    guard = ScopeGuard(cfg(), resolver=lambda h: ["203.0.113.10"])
    await EgressClient(guard).ensure_capacity(URL, 99)


# ---------------- R7 ----------------
def test_r7_error_messages_exact():
    assert str(RateLimitExceededError(LimitKind.HOST_RATE, 7)) == (
        "Rate limit exceeded: HOST_RATE; retry after 7s")
    assert str(RateLimitExceededError(LimitKind.TOTAL_BUDGET, None)) == (
        "Rate limit exceeded: TOTAL_BUDGET")
    assert str(RateLimitExceededError(LimitKind.CONCURRENCY, 1)) == (
        "Rate limit exceeded: CONCURRENCY; retry after 1s")


async def test_r7_message_has_no_target_text():
    client, _, _ = make_client(cfg(max_requests_total=1))
    await client.get(URL)
    with pytest.raises(RateLimitExceededError) as ei:
        await client.get(URL)
    assert "example.com" not in str(ei.value) and "http" not in str(ei.value)
