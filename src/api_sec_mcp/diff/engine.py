"""Diff algorithm (SPEC-008 R4/R5). Absence of a scan is never remediation."""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict

from api_sec_mcp.diff.identity import FindingKey
from api_sec_mcp.diff.store import Run, ScanFinding
from api_sec_mcp.models import Severity

_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


class Category(StrEnum):
    NEW = "NEW"
    RESOLVED = "RESOLVED"
    PERSISTING = "PERSISTING"
    SEVERITY_CHANGED = "SEVERITY_CHANGED"


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class DiffEntry(_Frozen):
    category: Category
    tool: str
    target: str
    rule: str
    location: str
    severity: Severity
    base_severity: Severity | None = None
    head_severity: Severity | None = None
    direction: Literal["up", "down"] | None = None


class FindingRef(_Frozen):
    rule: str
    severity: Severity
    location: str


class TargetRef(_Frozen):
    tool: str
    target: str
    findings: list[FindingRef]


class Summary(_Frozen):
    counts: dict[str, int]
    new_targets: int
    not_rescanned_targets: int
    regressions: int


class DiffReport(_Frozen):
    base_run: str
    head_run: str
    summary: Summary
    new: list[DiffEntry]
    resolved: list[DiffEntry]
    persisting: list[DiffEntry]
    severity_changed: list[DiffEntry]
    new_targets: list[TargetRef]
    not_rescanned: list[TargetRef]
    regressions: list[DiffEntry]

    def to_json(self) -> str:
        return json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def _sort_key(e: DiffEntry) -> tuple[str, str, str, str]:
    return (e.tool, e.target, e.rule, e.location)


def _index(findings: list[ScanFinding]) -> dict[tuple[str, str], ScanFinding]:
    return {(f.rule, f.location): f for f in findings}


def _ref(tool: str, target: str, findings: list[ScanFinding]) -> TargetRef:
    refs = sorted((FindingRef(rule=f.rule, severity=f.severity, location=f.location) for f in findings),
                  key=lambda r: (r.rule, r.location))
    return TargetRef(tool=tool, target=target, findings=refs)


def diff_runs(base: Run, head: Run, fail_on: Severity = Severity.MEDIUM) -> DiffReport:
    buckets: dict[Category, list[DiffEntry]] = {c: [] for c in Category}
    both = sorted(set(base.records) & set(head.records))

    for tool, target in both:
        b, h = _index(base.records[(tool, target)].findings), _index(head.records[(tool, target)].findings)
        for rule_loc in sorted(set(b) | set(h)):
            key = FindingKey(tool, target, *rule_loc)
            if rule_loc not in b:
                buckets[Category.NEW].append(DiffEntry(
                    category=Category.NEW, tool=key.tool, target=key.target, rule=key.rule,
                    location=key.location, severity=h[rule_loc].severity))
            elif rule_loc not in h:
                buckets[Category.RESOLVED].append(DiffEntry(
                    category=Category.RESOLVED, tool=key.tool, target=key.target, rule=key.rule,
                    location=key.location, severity=b[rule_loc].severity))
            elif b[rule_loc].severity == h[rule_loc].severity:
                buckets[Category.PERSISTING].append(DiffEntry(
                    category=Category.PERSISTING, tool=key.tool, target=key.target, rule=key.rule,
                    location=key.location, severity=h[rule_loc].severity))
            else:
                up = _RANK[h[rule_loc].severity] > _RANK[b[rule_loc].severity]
                buckets[Category.SEVERITY_CHANGED].append(DiffEntry(
                    category=Category.SEVERITY_CHANGED, tool=key.tool, target=key.target, rule=key.rule,
                    location=key.location, severity=h[rule_loc].severity,
                    base_severity=b[rule_loc].severity, head_severity=h[rule_loc].severity,
                    direction="up" if up else "down"))

    regressions = sorted(
        [e for e in buckets[Category.NEW] if _RANK[e.severity] >= _RANK[fail_on]]
        + [e for e in buckets[Category.SEVERITY_CHANGED]
           if e.direction == "up" and _RANK[e.severity] >= _RANK[fail_on]],
        key=_sort_key,
    )
    new_targets = [_ref(t, g, head.records[(t, g)].findings) for t, g in sorted(set(head.records) - set(base.records))]
    not_rescanned = [_ref(t, g, base.records[(t, g)].findings) for t, g in sorted(set(base.records) - set(head.records))]
    lists = {c: sorted(v, key=_sort_key) for c, v in buckets.items()}
    return DiffReport(
        base_run=base.run_id,
        head_run=head.run_id,
        summary=Summary(
            counts={c.name.lower(): len(lists[c]) for c in Category},
            new_targets=len(new_targets),
            not_rescanned_targets=len(not_rescanned),
            regressions=len(regressions),
        ),
        new=lists[Category.NEW],
        resolved=lists[Category.RESOLVED],
        persisting=lists[Category.PERSISTING],
        severity_changed=lists[Category.SEVERITY_CHANGED],
        new_targets=new_targets,
        not_rescanned=not_rescanned,
        regressions=regressions,
    )
