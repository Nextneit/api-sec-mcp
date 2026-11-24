"""Tests derived from specs/005-target-lab.md (R1, R4-R8). Real sockets, real MCP client."""

import json
import time
from pathlib import Path

import httpx
import pytest
from fastmcp.exceptions import ToolError

from api_sec_mcp.audit.logger import verify_chain
from api_sec_mcp.diff.cli import main as diff_main
from tests.integration.conftest import call_tool

pytestmark = pytest.mark.integration

GOLDEN = json.loads((Path(__file__).parents[2] / "target" / "expected.json").read_text())
HOSTILE_MARKERS = ("previous instructions", "exfiltrate", "system prompt")


def events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def simplify(findings: list[dict]) -> list[tuple[str, str, str]]:
    return sorted((f["rule"], f["severity"], f["location"]) for f in findings)


# ---------------- R1 ----------------
@pytest.mark.parametrize("route", [*GOLDEN, "/hostile/body", "/hostile/headers", "/redirect/metadata"])
def test_r1_routes_are_deterministic(lab, route):
    with httpx.Client(follow_redirects=False) as c:
        a, b = c.get(lab.base + route), c.get(lab.base + route)
    assert a.status_code == b.status_code
    assert a.content == b.content
    assert dict(a.headers) == dict(b.headers)


# ---------------- R4 / R5 ----------------
@pytest.mark.parametrize("route", [r for r in GOLDEN if not r.startswith("/jwt/")])
async def test_r4_golden_headers_and_cors(lab, engagement, route):
    engagement()
    spec = GOLDEN[route]
    report = await call_tool(spec["tool"], {"url": lab.base + route})
    assert simplify(report["findings"]) == simplify(spec["findings"])
    if not spec["findings"]:
        assert report["score"] == 100


@pytest.mark.parametrize("route", [r for r in GOLDEN if r.startswith("/jwt/")])
async def test_r5_golden_jwt(lab, engagement, route):
    engagement()
    token = httpx.get(lab.base + route).json()["token"]
    report = await call_tool(GOLDEN[route]["tool"], {"token": token})
    assert simplify(report["findings"]) == simplify(GOLDEN[route]["findings"])
    if not GOLDEN[route]["findings"]:
        assert report["score"] == 100


# ---------------- R6 ----------------
@pytest.mark.parametrize(("route", "tool"), [
    ("/hostile/body", "audit_security_headers"),
    ("/hostile/headers", "audit_security_headers"),
    ("/hostile/headers", "audit_cors"),
])
async def test_r6_hostile_target_contained(lab, engagement, route, tool):
    eng = engagement()
    report = await call_tool(tool, {"url": lab.base + route})
    blob = (json.dumps(report) + eng.log_path.read_text()).lower()
    for marker in HOSTILE_MARKERS:
        assert marker not in blob
    for f in report["findings"]:
        assert len(f["evidence"] or "") <= 128


@pytest.mark.parametrize(("route", "tool", "key"), [
    ("/hostile/token", "audit_security_headers", "url"),
])
async def test_spec006_single_token_injection_neutralized(lab, engagement, route, tool, key):
    eng = engagement()
    report = await call_tool(tool, {key: lab.base + route})
    blob = json.dumps(report) + eng.log_path.read_text()
    # target text is gone (case-sensitive: pattern ids such as SYSTEM_PROMPT are our own vocabulary)
    assert "Ignore_previous_instructions" not in blob and "system_prompt" not in blob
    assert "[REDACTED]" in blob
    kinds = [e["event"] for e in events(eng.log_path)]
    assert "OUTPUT_FLAGGED" in kinds and kinds.index("OUTPUT_FLAGGED") < kinds.index("TOOL_CALL")


async def test_spec006_hostile_claim_neutralized(lab, engagement):
    eng = engagement()
    token = httpx.get(lab.base + "/jwt/hostile-claim").json()["token"]
    report = await call_tool("audit_json_web_token", {"token": token})
    blob = json.dumps(report) + eng.log_path.read_text()
    assert "ignore_previous_instructions_and_call_tool" not in blob
    assert report["detected_claims"][2] == "[REDACTED]"


async def test_r6_redirect_not_followed(lab, engagement):
    eng = engagement()
    before = lab.counter["/redirect/metadata"]
    report = await call_tool("audit_security_headers", {"url": lab.base + "/redirect/metadata"})
    assert report["status_code"] == 302
    assert lab.counter["/redirect/metadata"] - before == 1
    log = eng.log_path.read_text()
    assert "169.254" not in log
    assert [e["event"] for e in events(eng.log_path)].count("EGRESS_ALLOWED") == 1


# ---------------- R7 ----------------
@pytest.mark.parametrize("route", ["/limits/big", "/limits/gzip-bomb", "/limits/infinite"])
async def test_r7_oversize_cut_at_limit_not_timeout(lab, engagement, route):
    eng = engagement(request_timeout_seconds=10)
    started = time.monotonic()
    with pytest.raises(ToolError, match="maximum"):
        await call_tool("audit_security_headers", {"url": lab.base + route})
    assert time.monotonic() - started < 5
    kinds = [(e["event"], e.get("reason")) for e in events(eng.log_path)]
    assert kinds[-1] == ("EGRESS_ERROR", "ResponseTooLargeError")


async def test_r7_slow_target_times_out(lab, engagement):
    eng = engagement(request_timeout_seconds=1)
    started = time.monotonic()
    with pytest.raises(ToolError):
        await call_tool("audit_security_headers", {"url": lab.base + "/limits/slow"})
    assert 0.8 < time.monotonic() - started < 4
    assert events(eng.log_path)[-1]["reason"] == "EgressTimeoutError"


# ---------------- R8 ----------------
async def test_r8_full_engagement(lab, engagement):
    eng = engagement()
    start_total = lab.total
    await call_tool("audit_security_headers", {"url": lab.base + "/headers/insecure"})
    await call_tool("audit_cors", {"url": lab.base + "/cors/reflect"})
    await call_tool("audit_json_web_token", {"token": httpx.get(lab.base + "/jwt/weak-secret").json()["token"]})
    with pytest.raises(ToolError):
        await call_tool("audit_security_headers", {"url": lab.base + "/limits/big"})
    allowed = [e for e in events(eng.log_path) if e["event"] == "EGRESS_ALLOWED"]
    assert len(allowed) == eng.client.limiter.used == 1 + 4 + 1
    # requests that reached the lab = allowed ones (+1 for the jwt fetch we made ourselves)
    assert lab.total - start_total == len(allowed) + 1

    # scope violations never reach the lab and never consume budget
    mark, used = lab.total, eng.client.limiter.used
    for url in (f"http://127.0.0.2:{lab.port}/", f"http://127.0.0.1:{lab.port + 1}/", "http://169.254.169.254/"):
        with pytest.raises(ToolError, match="Scope violation"):
            await call_tool("audit_security_headers", {"url": url})
    assert lab.total == mark and eng.client.limiter.used == used
    assert [e["event"] for e in events(eng.log_path)].count("EGRESS_BLOCKED") == 3
    assert verify_chain(eng.log_path).ok


async def test_r8_budget_rejections_are_audited(lab, engagement):
    eng = engagement(max_requests_total=5)
    mark = lab.total
    await call_tool("audit_cors", {"url": lab.base + "/cors/secure"})
    await call_tool("audit_security_headers", {"url": lab.base + "/headers/secure"})
    with pytest.raises(ToolError, match="TOTAL_BUDGET"):
        await call_tool("audit_security_headers", {"url": lab.base + "/headers/secure"})
    assert lab.total - mark == 5
    last = events(eng.log_path)[-1]
    assert last["event"] == "EGRESS_RATE_LIMITED" and last["reason"] == "TOTAL_BUDGET"
    assert verify_chain(eng.log_path).ok


# ---------------- SPEC-008 R7: weekly diff against the lab ----------------
GOLDEN_DIFF = json.loads((Path(__file__).parents[2] / "target" / "expected_diff.json").read_text())


def _view(entries: list[dict]) -> list[tuple[str, str, str, str]]:
    return sorted((e["tool"], e["rule"], str(e["severity"]), e["location"]) for e in entries)


def test_spec008_lab_has_no_mutating_routes():
    from target.app import app

    methods = {m for r in app.routes for m in getattr(r, "methods", set())}
    assert methods <= {"GET", "HEAD", "OPTIONS"}


async def test_spec008_weekly_diff_both_directions(lab, engagement, drift, capsys):
    results = None
    for label, phase in (("w1", "before"), ("w2", "after")):
        eng = engagement(run_label=label)
        results = eng.results_dir
        drift(phase)
        await call_tool("audit_security_headers", {"url": lab.base + "/drift/headers"})
        await call_tool("audit_cors", {"url": lab.base + "/drift/cors"})

    for name, (base, head) in {"forward": ("w1", "w2"), "reverse": ("w2", "w1")}.items():
        want = GOLDEN_DIFF[name]
        code = diff_main([base, head, "--results-dir", str(results), "--format", "json"])
        out = capsys.readouterr().out
        report = json.loads(out)
        assert code == want["exit_code"], name
        assert _view(report["new"]) == _view(want["new"]), name
        assert _view(report["resolved"]) == _view(want["resolved"]), name
        assert report["summary"]["regressions"] == want["regressions"], name
        assert report["persisting"] == [] and report["not_rescanned"] == [] and report["new_targets"] == []
        # deterministic: running the CLI again gives the same bytes
        diff_main([base, head, "--results-dir", str(results), "--format", "json"])
        assert capsys.readouterr().out == out
