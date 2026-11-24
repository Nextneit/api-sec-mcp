# SPEC-003 — `audit_cors` tool

Status: **implemented** (defaults chosen by the author's delegate; revisit in review) · Depends on: SPEC-001, SPEC-002

## Why
CORS misconfigurations are a top API finding and need active probing (`Origin` variations), which
is exactly what the egress layer exists to make safe.

## Design decisions
- **D1 — Fixed probe set, no agent-supplied origins.** The agent passes only `url`. Probe origins are
  constants/derived from the URL host, so runs are deterministic and an injected agent cannot use the
  tool to send arbitrary headers.
- **D2 — Hard request cap:** exactly `MAX_PROBES = 4` requests per call (3 GET + 1 OPTIONS).
  General rate limiting stays in SPEC-004.
- **D3 — Closed output:** evidence/location are fixed labels; target header values are never echoed.

## Requirements

### R1 — Probes (`tools/cors.py::inspect_cors(url, client)`)
| kind | method | Origin sent |
|---|---|---|
| `arbitrary` | GET | `https://evil.example` |
| `null` | GET | `null` |
| `suffix` | GET | `<scheme>://<host>.evil.example` |
| `preflight` | OPTIONS | `https://evil.example` + `Access-Control-Request-Method: PUT` |
- AC: exactly 4 requests reach the transport, in this order; the Origin values match the table;
  no way to add origins through the public API.

### R2 — GET classification (`acao` = `Access-Control-Allow-Origin`, `creds` = ACAC is exactly `true`)
| condition | rule | severity |
|---|---|---|
| `arbitrary`: acao == `*` and creds | `CORS_WILDCARD_WITH_CREDENTIALS` | MEDIUM |
| `arbitrary`: acao == `*`, no creds | `CORS_WILDCARD_ORIGIN` | LOW |
| `arbitrary`: acao == probe origin, creds | `CORS_REFLECTION_WITH_CREDENTIALS` | CRITICAL |
| `arbitrary`: acao == probe origin, no creds | `CORS_ORIGIN_REFLECTION` | MEDIUM |
| `null`: acao == `null`, creds / no creds | `CORS_NULL_ORIGIN_ALLOWED` | HIGH / MEDIUM |
| `suffix`: acao == probe origin AND `arbitrary` was not reflected | `CORS_WEAK_ORIGIN_VALIDATION` | HIGH |
- Comparison is exact and case-sensitive; lists / other values are ignored (no finding).
- AC: one parametrized case per row + a "safe server" case yielding zero findings and score 100.

### R3 — Preflight
- `CORS_PREFLIGHT_PERMISSIVE` (MEDIUM) when acao is the probe origin or `*` AND
  `Access-Control-Allow-Methods` contains (case-insensitive tokens) any of PUT/DELETE/PATCH, or `*`.
- Evidence lists only the matched methods from that closed set (`methods=DELETE,PUT`).
- AC: permissive → finding with exact methods; same methods but ACAO not matching → no finding.

### R4 — Bounded output
- `location` = `Header: Access-Control-Allow-Origin (probe: <kind>)` (or `...Allow-Methods (probe: preflight)`),
  `evidence` = `probe=<kind>;credentials=<true|false>` — never raw target values.
- AC: a hostile ACAO/ACAM value (500 chars, injection text) appears nowhere in the serialized report.

### R5 — Report & score
- `CorsReport(target_url, probes_sent, findings, score)`; `RuleId` gains the 7 `CORS_*` rules above.
- Score = 100 − Σ penalty(severity) with CRITICAL 40, HIGH 30, MEDIUM 20, LOW 5, floored at 0.
- AC: reflection+credentials → score 60; identical input → identical report.

### R6 — Errors
- `ScopeViolationError` on the first probe propagates and exactly one request attempt (the blocked one) is audited;
  no further probes are sent. Other `EgressError`s propagate (fail loudly, never partial reports).
- AC: out-of-scope URL → raises, transport never called, log contains one `EGRESS_BLOCKED`.

### R7 — MCP tool & audit
- `server.audit_cors(url)` sets `current_tool`, returns `report.model_dump()`, records one `TOOL_CALL`
  with `url` and `findings`.
- AC: a call produces 4×(ALLOWED, COMPLETED) + 1 TOOL_CALL = 9 events, all with `tool == "audit_cors"`;
  chain verifies.

### R8 — Docs
README tool list (replace "Upcoming"), test count, spec ticked.

## Non-goals
Custom origins, credentialed requests, cookie handling, `Vary: Origin` analysis, caching checks,
rate limiting (SPEC-004).

## Tasks
1. [x] Spec
2. [x] Tests R1–R7 (red)
3. [x] Implement models, `tools/cors.py`, server tool
4. [x] Ruff, README, commit
