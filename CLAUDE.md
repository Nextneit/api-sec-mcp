# api-sec-mcp

Security gateway between an autonomous pentesting LLM agent and an authorized HTTP target,
exposed as an MCP server (FastMCP). The value is the **security layer** (scope enforcement,
anti-SSRF, bounded factual output), not the checks. Read README.md for the threat model.

## Commands
- Install: `uv sync --all-groups`
- Test: `uv run pytest -q` (offline only: mocks for unit tests, loopback-only target lab for `integration`)
- Integration only: `uv run pytest -m integration` (starts `target/app.py` on an ephemeral 127.0.0.1 port)
- Lint: `uv run ruff check src tests` (must be clean before committing)
- Run server: `uv run api-sec-mcp` (needs `scope.yaml`; there is deliberately no fallback)

## Layout
- `egress/scope_guard.py` — deny-by-default allowlist, IP normalization, DNS validation. No FastMCP/httpx imports.
- `egress/client.py` — only code allowed to touch the network. Connects to the validated IP, no redirects, size limits.
- `tools/*.py` — one module per audit tool; take an `EgressClient` (or plain input) and return a pydantic report.
- `models.py` — `Finding`, reports, closed enums (`RuleId`, `Severity`), `safe_label`, `sanitize_evidence`.
- `server.py` — FastMCP wiring only; no logic.
- `audit/logger.py` — hash-chained JSONL audit log (`api-sec-verify` checks it). `egress/rate_limit.py` — budget/rate limits.
- `guards/` — planned (SPEC-006 sanitizer).
- `target/` — INTENTIONALLY VULNERABLE lab + `expected.json` golden findings. Never bind it beyond loopback; never import it from `src/`.
- `specs/` — numbered specs; `status` in the header says whether a spec may be implemented.

## Security invariants (never break; add a test when touching them)
1. No network I/O outside `EgressClient`; every request goes through `ScopeGuard.check` first.
2. Raw response bodies/headers never reach the LLM — tools return only `Finding`/report models.
3. Any string derived from a target (header, claim, alg, URL, exception text) must be bounded and
   sanitized (`safe_label` / `sanitize_evidence`) before entering a report. Never echo library
   exception messages.
4. Rule IDs and severities come from closed enums, never from target content.
5. Tools must not raise on hostile input; return a report with findings instead.
6. Fail closed: missing/invalid scope → refuse to start. No example-file fallback.
7. Blocking calls (DNS) stay off the event loop (`asyncio.to_thread`).
8. Every egress decision is audited before the request is sent (audit-or-deny); limits are fail-fast.
9. When a rule's severity/location changes, update `target/expected.json` in the same commit.

## Workflow: Spec-Driven Development
Non-trivial work follows `specs/NNN-name.md` → tests (red) → code (green) → README/ruff → commit.
- Write or update the spec first; each requirement has a testable acceptance criterion with an ID (R1…).
- Tests are named after the requirement (`test_r3_...`) and must fail before the implementation.
- Implement the minimum that makes them pass; do not expand scope beyond the spec's Non-goals.
- A spec is `draft` until the user approves it; do not implement a draft.
- Tick the spec's Tasks when done.

## Conventions
- Python ≥3.12, type hints on public functions in `src/`, line length 100, `from __future__ import annotations`.
- Tests are async-friendly (`asyncio_mode = "auto"`); never make real network calls.
- Commits: Conventional Commits (`feat(scope): ...`). Do not commit unless asked.
- Keep README test counts and tool names in sync when they change.
