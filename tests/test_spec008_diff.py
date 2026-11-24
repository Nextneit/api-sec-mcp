"""Tests derived from specs/008-diff-engine.md (R1-R6). The lab end-to-end (R7) is in integration/."""

import json
import random
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from api_sec_mcp import server
from api_sec_mcp.diff.cli import main
from api_sec_mcp.diff.engine import Category, diff_runs
from api_sec_mcp.diff.identity import FindingKey, normalize_target
from api_sec_mcp.diff.store import (
    ResultStore,
    ResultStoreError,
    Run,
    ScanFinding,
    ScanRecord,
)
from api_sec_mcp.egress.client import EgressClient
from api_sec_mcp.egress.scope_guard import ScopeConfig, ScopeGuard
from api_sec_mcp.models import Severity

H, C = "audit_security_headers", "audit_cors"
T1, T2 = "https://api.example.com/a", "https://api.example.com/b"


def F(rule, sev="high", loc=None, evidence=None):
    return ScanFinding(rule=rule, severity=sev, location=loc or f"Header: {rule}", evidence=evidence)


def R(run_id, tool, target, *findings):
    return ScanRecord(run_id=run_id, ts="2026-01-01T00:00:00+00:00", tool=tool, target=target,
                      findings=list(findings), score=50)


def run(run_id, *records):
    return Run.from_records(run_id, list(records))


# ---------------- R1 ----------------
@pytest.mark.parametrize(("raw", "expected"), [
    ("HTTPS://API.Example.com:443?x=1", "https://api.example.com/"),
    ("http://api.example.com:80/x?y#z", "http://api.example.com/x"),
    ("https://u:p@api.example.com:8443/Path/A", "https://api.example.com:8443/Path/A"),
    ("http://[::1]:8080", "http://[::1]:8080/"),
    ("https://h.com/" + "a" * 600, "https://h.com/" + "a" * 255),
])
def test_r1_normalize_target(raw, expected):
    assert normalize_target(raw) == expected


def test_r1_key_ignores_wording():
    a = F("X", "high", "L", "e1")
    b = F("X", "low", "L", "e2")
    ka = FindingKey(H, T1, a.rule, a.location)
    kb = FindingKey(H, T1, b.rule, b.location)
    assert ka == kb


# ---------------- R2 ----------------
def test_r2_concurrent_saves(tmp_path):
    store = ResultStore(tmp_path, "w1")
    recs = [R("w1", H, f"https://h.com/{i}", F("X")) for i in range(100)]
    with ThreadPoolExecutor(16) as ex:
        list(ex.map(store.save, recs))
    lines = (tmp_path / "w1.jsonl").read_text().splitlines()
    assert len(lines) == 100 and all(json.loads(x) for x in lines)
    assert len(ResultStore.load_run("w1", tmp_path).records) == 100


def test_r2_file_mode_and_last_wins(tmp_path):
    store = ResultStore(tmp_path, "w1")
    store.save(R("w1", H, T1, F("OLD")))
    store.save(R("w1", H, T1, F("NEW")))
    assert oct((tmp_path / "w1.jsonl").stat().st_mode & 0o777) == "0o600"
    loaded = ResultStore.load_run("w1", tmp_path)
    assert [f.rule for f in loaded.records[(H, T1)].findings] == ["NEW"]


@pytest.mark.parametrize("bad", ["../x", "a/b", "", ".hidden", "a b", "x" * 65, "w1\n"])
def test_r2_run_id_rejected(tmp_path, bad):
    with pytest.raises(ResultStoreError):
        ResultStore(tmp_path, bad)
    with pytest.raises(ResultStoreError):
        ResultStore.load_run(bad, tmp_path)


def test_r2_tampered_lines_rejected_with_line_number(tmp_path):
    store = ResultStore(tmp_path, "w1")
    store.save(R("w1", H, T1, F("X")))
    p = tmp_path / "w1.jsonl"
    good = p.read_text()
    for bad_line in ["not json", '{"run_id":"w1"}', json.dumps({**json.loads(good), "extra": 1}),
                     json.dumps({**json.loads(good), "run_id": "other"}),
                     json.dumps({**json.loads(good), "target": "https://h/\x01"})]:
        p.write_text(good + bad_line + "\n")
        with pytest.raises(ResultStoreError, match=r"w1\.jsonl:2"):
            ResultStore.load_run("w1", tmp_path)


def test_r2_load_by_path_and_missing(tmp_path):
    ResultStore(tmp_path, "w1").save(R("w1", H, T1, F("X")))
    assert ResultStore.load_run(str(tmp_path / "w1.jsonl"), tmp_path).run_id == "w1"
    with pytest.raises(ResultStoreError, match="not found"):
        ResultStore.load_run("nope", tmp_path)


# ---------------- R3 ----------------
def _client(tmp_path, results, handler=None):
    guard = ScopeGuard(
        ScopeConfig(allowed_hosts=["api.example.com"], allowed_ips=["203.0.113.10"],
                    allowed_ports=[443], allowed_schemes=["https"]),
        resolver=lambda h: ["203.0.113.10"])
    transport = httpx.MockTransport(handler or (lambda r: httpx.Response(200, headers={"Server": "Apache/2.4.1"})))
    return EgressClient(guard, transport=transport, results=results)


async def test_r3_server_records_one_scan_per_call(tmp_path, monkeypatch):
    store = ResultStore(tmp_path / "res", "w1")
    monkeypatch.setattr(server, "_CLIENT", _client(tmp_path, store))
    data = await server.audit_security_headers("HTTPS://api.example.com:443/x?token=1")
    rec = ResultStore.load_run("w1", tmp_path / "res").records[(H, "https://api.example.com/x")]
    assert len(rec.findings) == len(data["findings"]) and rec.score == data["score"]
    assert "token" not in (tmp_path / "res" / "w1.jsonl").read_text()
    await server.audit_cors("https://api.example.com/y")
    assert len(ResultStore.load_run("w1", tmp_path / "res").records) == 2


async def test_r3_jwt_and_failed_calls_not_recorded(tmp_path, monkeypatch):
    store = ResultStore(tmp_path / "res", "w1")
    monkeypatch.setattr(server, "_CLIENT", _client(tmp_path, store))
    await server.audit_json_web_token("a.b.c")
    with pytest.raises(Exception):  # noqa: B017  (scope violation)
        await server.audit_security_headers("https://169.254.169.254/")
    assert not (tmp_path / "res" / "w1.jsonl").exists()


async def test_r3_unwritable_results_fails_the_call(tmp_path, monkeypatch):
    blocker = tmp_path / "res"
    blocker.write_text("i am a file, not a directory")
    monkeypatch.setattr(server, "_CLIENT", _client(tmp_path, ResultStore(blocker, "w1")))
    with pytest.raises(ResultStoreError):
        await server.audit_security_headers("https://api.example.com/x")


def test_r3_config_and_gitignore(tmp_path):
    assert ScopeConfig().results_dir == "results" and ScopeConfig().run_label is None
    with pytest.raises(ValueError):
        ScopeConfig(run_label="../x")
    assert ScopeConfig(run_label="2026-w47").run_label == "2026-w47"
    assert "results/" in open(".gitignore").read()


def test_r3_build_client_uses_label_or_date(tmp_path):
    cfg = dict(audit_log_path=str(tmp_path / "a.jsonl"), results_dir=str(tmp_path / "r"))
    c1 = server.build_egress_client(ScopeGuard(ScopeConfig(run_label="w9", **cfg)))
    assert c1.results.run_id == "w9"
    c2 = server.build_egress_client(ScopeGuard(ScopeConfig(**cfg)))
    import re
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", c2.results.run_id)


# ---------------- R4 ----------------
def _by(report, cat):
    return [(e.tool, e.target, e.rule, e.location) for e in getattr(report, cat)]


def test_r4_categories():
    base = run("a", R("a", H, T1, F("GONE"), F("STAY"), F("UP", "low"), F("DOWN", "high")))
    head = run("b", R("b", H, T1, F("STAY"), F("UP", "high"), F("DOWN", "low"), F("FRESH")))
    r = diff_runs(base, head)
    assert [e.rule for e in r.new] == ["FRESH"]
    assert [e.rule for e in r.resolved] == ["GONE"]
    assert [e.rule for e in r.persisting] == ["STAY"]
    changed = {e.rule: (e.direction, e.base_severity, e.head_severity) for e in r.severity_changed}
    assert changed == {"UP": ("up", "low", "high"), "DOWN": ("down", "high", "low")}
    assert r.summary.counts == {"new": 1, "resolved": 1, "persisting": 1, "severity_changed": 2}


def test_r4_absence_is_not_resolution():
    base = run("a", R("a", H, T1, F("X")), R("a", H, T2, F("Y")))
    head = run("b", R("b", H, T2))  # T1 was not re-scanned, T2 was and Y is gone
    r = diff_runs(base, head)
    assert [e.rule for e in r.resolved] == ["Y"]
    assert [(t.tool, t.target) for t in r.not_rescanned] == [(H, T1)]
    assert r.summary.not_rescanned_targets == 1


def test_r4_new_targets_are_informational_and_tools_do_not_cross():
    base = run("a", R("a", H, T1, F("X")))
    head = run("b", R("b", C, T1, F("Z")))
    r = diff_runs(base, head)
    assert r.new == [] and r.resolved == []
    assert [(t.tool, t.target) for t in r.new_targets] == [(C, T1)]
    assert [(t.tool, t.target) for t in r.not_rescanned] == [(H, T1)]
    assert r.new_targets[0].findings[0].rule == "Z"


def test_r4_identity_ignores_evidence_and_description():
    base = run("a", R("a", H, T1, F("X", "high", "L", "old")))
    head = run("b", R("b", H, T1, F("X", "high", "L", "totally different")))
    r = diff_runs(base, head)
    assert [e.rule for e in r.persisting] == ["X"] and not r.new and not r.resolved


# ---------------- R5 ----------------
def test_r5_regressions_and_threshold():
    base = run("a", R("a", H, T1, F("UPLOW", "info"), F("UPHIGH", "low")))
    head = run("b", R("b", H, T1, F("NEWHIGH", "high"), F("NEWLOW", "low"),
                       F("UPLOW", "low"), F("UPHIGH", "high")))
    r = diff_runs(base, head)
    assert sorted(e.rule for e in r.regressions) == ["NEWHIGH", "UPHIGH"]
    assert r.summary.regressions == 2
    assert sorted(e.rule for e in diff_runs(base, head, fail_on=Severity.LOW).regressions) == [
        "NEWHIGH", "NEWLOW", "UPHIGH", "UPLOW"]
    assert diff_runs(base, head, fail_on=Severity.CRITICAL).regressions == []


def test_r5_deterministic_under_shuffle_and_self_diff_clean():
    recs_b = [R("a", H if i % 2 else C, f"https://h.com/{i % 5}", F("A"), F("B", "low")) for i in range(40)]
    recs_h = [R("b", r.tool, r.target, F("A"), F("C")) for r in recs_b]
    outputs = set()
    for seed in range(5):
        random.Random(seed).shuffle(recs_b)
        random.Random(seed + 9).shuffle(recs_h)
        outputs.add(diff_runs(run("a", *recs_b), run("b", *recs_h)).to_json())
    assert len(outputs) == 1
    same = diff_runs(run("a", *recs_b), run("a", *recs_b))
    assert same.summary.counts["persisting"] > 0 and same.summary.regressions == 0
    assert not (same.new or same.resolved or same.severity_changed)


def test_r5_sorted_lists():
    base = run("a", R("a", H, T2, F("Z")), R("a", C, T1, F("A")), R("a", H, T1, F("M")))
    head = run("b", R("b", H, T2), R("b", C, T1), R("b", H, T1))
    keys = [(e.tool, e.target, e.rule, e.location) for e in diff_runs(base, head).resolved]
    assert keys == sorted(keys)


# ---------------- R6 ----------------
def _write(tmp, rid, *recs):
    store = ResultStore(tmp, rid)
    for r in recs:
        store.save(r)


def test_r6_exit_codes(tmp_path, capsys):
    _write(tmp_path, "w1", R("w1", H, T1, F("OLD", "high"), F("KEEP", "low")))
    _write(tmp_path, "w2", R("w2", H, T1, F("KEEP", "low")))
    _write(tmp_path, "w3", R("w3", H, T1, F("KEEP", "low"), F("BAD", "high")))
    d = str(tmp_path)
    assert main(["w1", "w2", "--results-dir", d]) == 0   # only fixes
    assert main(["w2", "w3", "--results-dir", d]) == 1   # new HIGH
    assert main(["w2", "w3", "--results-dir", d, "--fail-on", "critical"]) == 0
    assert main(["w1", "missing", "--results-dir", d]) == 2


def test_r6_json_output_matches_report_and_text_mode(tmp_path, capsys):
    _write(tmp_path, "w1", R("w1", H, T1, F("OLD", "high")))
    _write(tmp_path, "w2", R("w2", H, T1))
    main(["w1", "w2", "--results-dir", str(tmp_path), "--format", "json"])
    out = capsys.readouterr().out
    expected = diff_runs(ResultStore.load_run("w1", tmp_path), ResultStore.load_run("w2", tmp_path))
    assert out.strip() == expected.to_json()
    main(["w1", "w2", "--results-dir", str(tmp_path)])
    text = capsys.readouterr().out
    assert "RESOLVED" in text and "OLD" in text and T1 in text


def test_r6_tampered_file_gives_exit_2_without_traceback(tmp_path, capsys):
    _write(tmp_path, "w1", R("w1", H, T1, F("X")))
    _write(tmp_path, "w2", R("w2", H, T1, F("X")))
    with open(tmp_path / "w2.jsonl", "a") as f:
        f.write("garbage\n")
    assert main(["w1", "w2", "--results-dir", str(tmp_path)]) == 2
    err = capsys.readouterr().err
    assert "w2.jsonl:2" in err and "Traceback" not in err


def test_r6_category_enum_is_closed():
    assert {c.value for c in Category} == {"NEW", "RESOLVED", "PERSISTING", "SEVERITY_CHANGED"}
