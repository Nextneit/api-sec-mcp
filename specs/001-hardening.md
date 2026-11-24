# SPEC-001 — Hardening: scope config, JWT output bounds, async DNS

Status: approved · Owner: Nextneit · Flow: spec → tests (red) → code (green) → README

## Why
Review found places where the implementation contradicts the README threat model
(target-controlled text escaping sanitization, config silently ignored, fail-open scope).

## Requirements (each one maps to tests; IDs are referenced in test names)

### R1 — Scope config is honored
- `max_response_bytes` and `request_timeout_seconds` from `scope.yaml` MUST reach `EgressClient`.
- Implementation: `ScopeGuard.config` property; `server.build_egress_client(guard)`.
- AC: `build_egress_client(guard)` yields client with the configured timeout and byte limit.

### R2 — Scope is fail-closed
- `load_scope_guard()` MUST NOT fall back to `scope.example.yaml`.
- Missing file → `FileNotFoundError` whose message tells the operator to copy the example.
- AC: with no `scope.yaml` and an existing example file, loading raises.

### R3 — JWT output is bounded and sanitized
- Every string derived from the token (alg, claim names, in locations/descriptions/evidence/
  `detected_claims`) passes through `safe_label()`: charset `[A-Za-z0-9_.:-]`, others → `_`, max 64 chars.
- Descriptions MUST NOT include exception text from PyJWT.
- `detected_claims` capped at 50 entries.
- `algorithm` ≤ 32 chars after sanitization.
- AC: token with 500-char claim name / 500-char alg / prompt-injection-like claim name produces a
  report with no `ValidationError`, no characters outside the charset, no exception text.

### R4 — `audit_jwt` never raises
- Any `str` input returns a `JwtReport`. Token > 8192 chars → `JWT_MALFORMED_STRUCTURE` finding.
- Non-numeric `exp`/`iat` (list, dict, bool, string, inf, nan) are treated as absent/invalid:
  `exp` invalid ⇒ `JWT_NO_EXPIRY`; `iat` invalid ⇒ ignored for lifetime check.
- AC: parametrized test over hostile `exp`/`iat` values and garbage tokens; none raise.

### R5 — DNS never blocks the event loop
- `EgressClient.request` runs `ScopeGuard.check` via `asyncio.to_thread`.
- AC: with a resolver that sleeps 0.3s, a concurrent ticker task keeps ticking during `request`.

## Non-goals
CORS tool, diff engine, audit log (future specs 002+).

## Tasks
1. [x] Spec
2. [ ] Tests for R1–R5 (expect red)
3. [ ] Implement R1–R5
4. [ ] Ruff cleanup (tests exempt from ANN), README sync, commit
