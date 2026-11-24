"""Result store: one append-only JSONL file per run (SPEC-008 R2)."""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from api_sec_mcp.diff.identity import normalize_target
from api_sec_mcp.models import Severity

RUN_ID_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")
_ASCII = r"^[\x20-\x7E]*$"


class ResultStoreError(Exception):
    """A result could not be saved, found or validated."""


class ScanFinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    rule: str = Field(..., pattern=r"^[A-Z][A-Z0-9_]{0,63}$")
    severity: Severity
    location: str = Field(..., max_length=128, pattern=_ASCII)
    evidence: str | None = Field(default=None, max_length=128, pattern=_ASCII)


class ScanRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: str = Field(..., pattern=RUN_ID_RE.pattern)
    ts: str = Field(..., max_length=40)
    tool: str = Field(..., pattern=r"^[a-z][a-z0-9_]{0,63}$")
    target: str = Field(..., min_length=1, max_length=512, pattern=_ASCII)
    findings: list[ScanFinding]
    score: int = Field(..., ge=0, le=100)


class Run:
    """All scans of one run; for each (tool, target) the last record wins."""

    def __init__(self, run_id: str, records: dict[tuple[str, str], ScanRecord]) -> None:
        self.run_id = run_id
        self.records = records

    @classmethod
    def from_records(cls, run_id: str, records: list[ScanRecord]) -> Run:
        return cls(run_id, {(r.tool, r.target): r for r in records})


def _check_run_id(run_id: str) -> str:
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        raise ResultStoreError("Invalid run id (allowed: letters, digits, '_', '.', '-'; max 64)")
    return run_id


class ResultStore:
    def __init__(self, directory: Path | str, run_id: str) -> None:
        self.directory = Path(directory)
        self.run_id = _check_run_id(run_id)

    def save(self, record: ScanRecord) -> None:
        """Append one record to ``<dir>/<run_id>.jsonl`` (mode 0600, single atomic write)."""
        _check_run_id(record.run_id)
        line = json.dumps(record.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.directory / f"{record.run_id}.jsonl",
                         os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, (line + "\n").encode())
            finally:
                os.close(fd)
        except OSError as exc:
            raise ResultStoreError(f"Cannot save result: {type(exc).__name__}") from exc

    def record(self, tool: str, url: str, findings: list[Any], score: int) -> ScanRecord:
        """Build a record from a (guarded) report and save it. *findings* are dicts or models."""
        try:
            rec = ScanRecord(
                run_id=self.run_id,
                ts=datetime.now(UTC).isoformat(timespec="seconds"),
                tool=tool,
                target=normalize_target(url),
                findings=[_to_scan_finding(f) for f in findings],
                score=score,
            )
        except (ValidationError, TypeError, KeyError, AttributeError) as exc:
            raise ResultStoreError(f"Report cannot be recorded: {type(exc).__name__}") from exc
        self.save(rec)
        return rec

    @staticmethod
    def load_run(ref: str, directory: Path | str = "results") -> Run:
        """Load a run by id (inside *directory*) or by file path; every line is validated."""
        if RUN_ID_RE.fullmatch(ref):
            path = Path(directory) / f"{ref}.jsonl"
        elif os.path.isfile(ref):
            path = Path(ref)
        else:
            raise ResultStoreError(f"Invalid run reference {ref[:64]!r}: not a run id or a file")
        if not path.is_file():
            raise ResultStoreError(f"Run not found: {path}")
        run_id = path.name.removesuffix(".jsonl")
        records: list[ScanRecord] = []
        with open(path, encoding="utf-8") as f:
            for lineno, line in enumerate(f, start=1):
                if not line.strip():
                    continue
                where = f"{path.name}:{lineno}"
                try:
                    rec = ScanRecord.model_validate_json(line)
                except ValidationError as exc:
                    raise ResultStoreError(f"{where}: invalid record ({exc.error_count()} errors)") from exc
                if rec.run_id != run_id:
                    raise ResultStoreError(f"{where}: record belongs to run {rec.run_id!r}, not {run_id!r}")
                records.append(rec)
        return Run.from_records(run_id, records)


def _to_scan_finding(f: Any) -> ScanFinding:  # noqa: ANN401
    get = f.get if isinstance(f, dict) else lambda k, d=None: getattr(f, k, d)
    rule, severity = get("rule"), get("severity")
    return ScanFinding(
        rule=getattr(rule, "value", rule),
        severity=getattr(severity, "value", severity),
        location=get("location"),
        evidence=get("evidence"),
    )
