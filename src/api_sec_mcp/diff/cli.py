"""``api-sec-diff BASE HEAD`` — compare two runs (SPEC-008 R6). Exit: 0 clean, 1 regressions, 2 error."""

from __future__ import annotations

import argparse
import sys

from api_sec_mcp.diff.engine import DiffEntry, DiffReport, diff_runs
from api_sec_mcp.diff.store import ResultStore, ResultStoreError
from api_sec_mcp.models import Severity


def _text(report: DiffReport) -> str:
    out = [f"Diff {report.base_run} -> {report.head_run}"]
    sections: list[tuple[str, list[DiffEntry]]] = [
        ("NEW", report.new), ("RESOLVED", report.resolved),
        ("SEVERITY_CHANGED", report.severity_changed), ("PERSISTING", report.persisting),
    ]
    entries = [(label, e) for label, items in sections for e in items]
    targets = sorted({(e.tool, e.target) for _, e in entries})
    for tool, target in targets:
        out.append(f"\n== {tool} {target}")
        for label, e in entries:
            if (e.tool, e.target) == (tool, target):
                extra = f" ({e.base_severity.value} -> {e.head_severity.value})" if e.direction else ""
                out.append(f"  {label:<16} {e.severity.value:<8} {e.rule}  {e.location}{extra}")
    for title, refs in (("New targets (no baseline)", report.new_targets),
                        ("Not re-scanned (nothing can be concluded)", report.not_rescanned)):
        if refs:
            out.append(f"\n{title}:")
            out.extend(f"  {r.tool} {r.target} ({len(r.findings)} findings)" for r in refs)
    s = report.summary
    counts = " ".join(f"{k}={v}" for k, v in s.counts.items())
    out.append(f"\nSummary: {counts} regressions={s.regressions}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="api-sec-diff", description="Compare two assessment runs.")
    parser.add_argument("base", help="run id or path of the older run")
    parser.add_argument("head", help="run id or path of the newer run")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--fail-on", choices=[s.value for s in Severity], default="medium")
    parser.add_argument("--results-dir", default="results")
    args = parser.parse_args(argv)
    try:
        base = ResultStore.load_run(args.base, args.results_dir)
        head = ResultStore.load_run(args.head, args.results_dir)
    except ResultStoreError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    report = diff_runs(base, head, Severity(args.fail_on))
    print(report.to_json() if args.format == "json" else _text(report))
    return 1 if report.regressions else 0


if __name__ == "__main__":
    raise SystemExit(main())
