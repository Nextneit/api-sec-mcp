# SPEC-008 — Weekly diff engine

Status: **approved** (all open questions resolved with the recommendations below) · Depends on: SPEC-001…005 (uses the Target Lab's deterministic findings)

> Numbering follows the roadmap: 006 Sanitizer guard and 007 extra JWT checks are still pending and do not
> block this spec.

## Why
The thesis promises that "identical target configurations produce identical findings, enabling weekly diffs
to track regressions or remediations". Today findings are returned to the agent and then forgotten: nothing
is persisted, so nothing can be compared. A pentester running the same engagement every week needs to know,
in seconds, **what is new, what was fixed, and what got worse**.

## Design decisions (challenge these during review)
- **D1 — Absence of a scan is not remediation.** A finding is only `RESOLVED` if the same `(tool, target)`
  was scanned again in the newer run and no longer shows it. Targets not re-scanned (or whose scan failed)
  are reported separately and never produce `RESOLVED`. This is the main correctness property.
- **D2 — Identity ignores wording.** A finding is identified by `(tool, target, rule, location)`. `severity`,
  `description` and `evidence` are not part of identity, so rewording or re-scoring never fakes a new finding.
- **D3 — Snapshots are written by the gateway, read by the operator.** The server appends one record per
  completed tool call to `results/<run_id>.jsonl`. Diffing is a CLI for the human; there is **no MCP tool**
  to read results or diffs, so the agent cannot see (or poison) the weekly comparison.
- **D4 — Fail loudly.** If a record cannot be saved, the tool call fails (same philosophy as audit-or-deny):
  a silent gap would later look like a remediation.
- **D5 — Deterministic output.** Same two runs → byte-identical JSON, regardless of file order or line order.
- **D6 — Metadata hygiene:** records hold only already-bounded report data (rule, severity, location,
  sanitized evidence, score) and a normalized target; no headers, bodies, tokens or query strings.

## Requirements

### R1 — Target normalization and finding identity (`diff/identity.py`)
- `normalize_target(url)`: lowercase scheme and host, drop userinfo/query/fragment, drop the default port
  (80/http, 443/https), empty path → `/`, path case preserved and capped at 256 chars.
- `FindingKey = (tool, target, rule, location)`.
- AC: `HTTPS://API.Example.com:443?x=1` and `https://api.example.com/` normalize identically; two findings
  that differ only in severity/description/evidence share a key.

### R2 — Result store (`diff/store.py`)
- `ScanRecord`: `run_id, ts (UTC ISO), tool, target, findings[{rule, severity, location, evidence}], score`
  (pydantic, frozen, `extra="forbid"`).
- `ResultStore(dir)`: `save(record)` appends one JSON line to `<dir>/<run_id>.jsonl` (mode `0600`);
  `load_run(run_id_or_path) -> Run` validates every line through the model and rejects malformed or foreign
  lines with a clear error (no partial loads).
- `Run`: for each `(tool, target)` keeps the **last** record (re-scanning inside a run overwrites).
- `run_id` charset `[A-Za-z0-9_.-]{1,64}`; anything else is rejected (no path traversal).
- AC: 100 concurrent saves yield 100 valid lines; a hand-edited invalid line makes `load_run` fail naming the
  line number; `run_id="../x"` is rejected; saving the same `(tool, target)` twice loads as one record (the
  second).

### R3 — Run identification and server wiring
- `ScopeConfig.run_label: str | None` (charset as above) and `results_dir: str = "results"`.
- `run_id` = `run_label` if set, otherwise the UTC date `YYYY-MM-DD` at server start.
- After each successful `audit_security_headers` and `audit_cors` call the server saves a `ScanRecord`
  (tool name, normalized URL, findings, score) **before** returning the report. `audit_json_web_token` is not
  recorded (see Non-goals). A save failure raises `ResultStoreError` and the call fails.
- AC: a headers call produces exactly one record; a failing egress call (timeout, out of scope) produces none;
  an unwritable results dir fails the call; `results/` is git-ignored.

### R4 — Diff algorithm (`diff/engine.py::diff_runs(base, head) -> DiffReport`)
For every `(tool, target)` pair present in **both** runs, compare finding sets by key:
| category | condition |
|---|---|
| `NEW` | key only in head |
| `RESOLVED` | key only in base |
| `PERSISTING` | key in both, same severity |
| `SEVERITY_CHANGED` | key in both, different severity (`direction: up|down`, plus both values) |
Pairs in only one run:
- only in head → `new_targets` (their findings are listed informationally, never counted as `NEW`)
- only in base → `not_rescanned` (never produce `RESOLVED`)
- AC: base has finding F on target T, head has no record for T → F is **not** `RESOLVED`; head has a record for
  T with no F → `RESOLVED`; a target scanned by headers in base and only by cors in head yields no cross-tool
  comparison.

### R5 — `DiffReport` model and determinism
- Fields: `base_run`, `head_run`, `summary` (counts per category, counts of new/not-rescanned targets,
  `regressions`), and the lists above, each sorted by `(tool, target, rule, location)`.
- `regressions` = `NEW` findings with severity ≥ MEDIUM, plus `SEVERITY_CHANGED` with `direction=up` whose
  new severity is ≥ MEDIUM (threshold configurable in the CLI).
- Serialization uses sorted keys and fixed separators.
- AC: diffing the same inputs twice, and with the input lines shuffled, gives identical bytes; diffing a run
  with itself gives only `PERSISTING` and zero regressions.

### R6 — CLI (`api-sec-diff BASE HEAD [--format text|json] [--fail-on LEVEL] [--results-dir DIR]`)
- `BASE`/`HEAD` are run ids (resolved in the results dir) or file paths. `--fail-on` defaults to `medium`.
- Exit codes: `0` no regressions at or above the threshold, `1` regressions found, `2` usage/IO/validation error.
- Text output groups by target and prints, per finding, rule, severity and location; strings re-checked
  against the bounded charset on load (the files are operator-controlled but may have been edited).
- AC: exit codes for each case; `--format json` output equals `DiffReport` serialization; a tampered file
  gives exit 2 with the offending line number and no traceback.

### R7 — End-to-end against the Target Lab
- The lab gets two drift routes, `/drift/headers` and `/drift/cors`, whose behavior follows
  `app.state.phase` (`before` = insecure/reflecting, `after` = secure). Phase is changed only by the test
  harness (in-process); the app exposes **no route** that mutates state.
- Test: run the real tools through MCP in phase `before` (run `w1`), flip to `after` (run `w2`), run the CLI:
  headers `CSP_MISSING … POWERED_BY_LEAK` and the CORS findings are `RESOLVED`, nothing is `NEW`, exit code 0;
  reverse the order (`w2` → `w1`) and every one of them is `NEW` and a regression, exit code 1.
- Expected diff lives in `target/expected_diff.json` (golden, like `expected.json`).
- AC: both directions asserted; the result is identical when run twice.

### R8 — Docs
README "Weekly diff" section (workflow: pick a `run_label` per week, run the engagement, run `api-sec-diff`),
threat-model note (results integrity is the operator's host, same boundary as the audit log), `.gitignore`,
`CLAUDE.md` invariant "changing a rule's identity fields requires updating the golden diff", test count.

## Non-goals
JWT diffs (tokens have no stable target), trends over more than two runs, HTML/PDF reports, accepted-risk
suppression or baselines, diffing evidence values, scheduling/automation, exposing results or diffs to the agent,
signing or hash-chaining result files (candidate for a later spec; host compromise is out of scope).

## Resolved questions (decisions taken)
1. **Fail the tool call when a snapshot cannot be saved (D4)** — recommended. Alternative: log a warning and
   continue, which risks silent holes that later read as "fixed".
2. **Results on by default (`results/`)** — recommended, git-ignored; an opt-out flag adds a path where weekly
   diffs silently stop working.
3. **Default `run_id` = UTC date** — recommended for weekly cadence; operators who run several times a day set
   `run_label`. Same id appends and the last scan per target wins.
4. **Severity decreases as `SEVERITY_CHANGED(direction=down)`** — recommended (an "improved" signal) rather than
   folding them into `PERSISTING`.
5. **JWT excluded in v1** — recommended; hashing tokens as targets would almost never match week to week.
6. **Query strings dropped from the target** — recommended for safety (no secrets in results), at the cost that
   `/api?id=1` and `/api?id=2` collide (last scan wins). Documented.

## Tasks
1. [x] Review/approve spec (answer open questions)
2. [ ] Tests R1–R7 (red), including lab drift routes and `target/expected_diff.json`
3. [ ] Implement `diff/` package, config fields, server recording, CLI entry point
4. [ ] Ruff, README, CLAUDE.md, commit
