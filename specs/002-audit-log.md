# SPEC-002 — Egress audit log

Status: **implemented** (decisions below taken by the author's delegate; revisit in review) · Depends on: SPEC-001 · Flow: spec → tests (red) → code (green) → README

## Why
In a real engagement the operator must be able to prove what the agent touched and what the
gateway refused. Today nothing is recorded. The log is also the foundation for rate limiting
(SPEC-004) and the weekly diff engine (SPEC-007).

## Design decisions (challenge these during review)
- **D1 — Audit-or-deny:** if an event cannot be written, the request is NOT sent.
- **D2 — Metadata only:** never log headers, bodies, query values, credentials or JWT contents.
- **D3 — Tamper evidence:** each line carries the SHA-256 of the previous line (hash chain).
  It is evidence of accidental or naive tampering, not a defence against a compromised host
  (that is already out of scope in the threat model).
- **D4 — Format:** JSON Lines, append-only, one event per line, UTC timestamps.

## Requirements

### R1 — `AuditLog` component (`src/api_sec_mcp/audit/logger.py`)
- `AuditLog(path)`; `async record(event: EventType, **fields)` builds an `AuditEvent` (adds `seq`, `ts`, `prev`) and appends exactly one line, serialized with
  an `asyncio.Lock`; each write is one `os.write` on an `O_APPEND` fd (no interleaving).
- File is created with mode `0o600`; parent dir must exist.
- AC: 100 concurrent `record` calls yield 100 valid JSON lines, no interleaving, in `seq` order.

### R2 — Event schema (`AuditEvent`, pydantic, `extra="forbid"`, frozen)
Fields: `seq:int`, `ts:str(UTC ISO-8601)`, `prev:str(64 hex | "0"*64)`, `event:EventType`,
`tool:str|None`, `method:str|None`, `url:str|None`, `host:str|None`, `resolved_ip:str|None`,
`status_code:int|None`, `bytes_read:int|None`, `duration_ms:int|None`, `reason:str|None`
(max 128, passed through `safe_label`-style sanitization), `findings:int|None`.
- `EventType` is a closed enum: `TOOL_CALL`, `EGRESS_BLOCKED`, `EGRESS_ALLOWED` (scope approved, written BEFORE sending), `EGRESS_COMPLETED`, `EGRESS_ERROR`.
- `tool` defaults to the `current_tool` ContextVar set by the MCP tool wrapper.
- AC: unknown fields rejected; `reason` with control chars / >128 chars is bounded and sanitized.

### R3 — URL redaction (D2)
- Logged `url` = `scheme://host[:port]/path` with userinfo, query and fragment removed;
  path capped at 256 chars and sanitized.
- AC: `https://u:p@api.example.com/x?token=abc#f` logs as `https://api.example.com/x`.

### R4 — Egress integration
- `EgressClient(..., audit: AuditLog | None = None)`.
- Every `request()` records: `EGRESS_BLOCKED` (reason = scope violation reason) when `ScopeGuard`
  refuses, written BEFORE the exception propagates; otherwise `EGRESS_ALLOWED` (host, resolved_ip)
  BEFORE any I/O, then `EGRESS_COMPLETED` (status_code, bytes_read, duration_ms) or `EGRESS_ERROR`
  (reason = exception class name only; duration_ms).
- AC: blocked → exactly [BLOCKED]; success → [ALLOWED, COMPLETED]; timeout/connect/too-large → [ALLOWED, ERROR].

### R5 — Audit-or-deny (D1)
- If `AuditLog.record` raises, `request()` raises `AuditError`; if the pre-send `EGRESS_ALLOWED`
  fails, no network I/O occurs. A failure on a post-send event discards the response.
- AC: with a log whose `record` raises, the MockTransport handler is never invoked and the caller gets `AuditError`.

### R6 — Tool-level events
- Each MCP tool records `TOOL_CALL` (tool name, sanitized target url if any, `findings` count).
- `audit_json_web_token` logs only `tool` and `bytes_read=len(token)`; NEVER the token or claims.
- AC: after calling the JWT tool with a distinctive token, the log file does not contain any
  substring of that token.

### R7 — Chain verification
- `verify_chain(path) -> VerifyResult(ok: bool, bad_seq: int | None, lines: int)`.
- AC: mutating a line, deleting a non-final line, or reordering lines makes `ok=False` and points at the first bad `seq`. (Truncating the tail is undetectable without an external anchor — documented limitation.)
- Continuing an existing log after restart resumes `seq` and `prev` from the last line.

### R8 — Configuration & wiring
- `ScopeConfig.audit_log_path: str = "audit.jsonl"`; `server.build_egress_client` creates the `AuditLog`.
- `audit.jsonl` added to `.gitignore`.
- AC: config value reaches the client; default path used when omitted.

## Non-goals
Log rotation, remote shipping, encryption, a log-reading MCP tool (the agent must not read its own
audit trail), rate limiting (SPEC-004).

## Open questions
1. Hash chain: **kept** (small: ~30 lines).
2. `reason`: **sanitized free text** (bounded 128) for now; a closed enum of violation kinds is deferred to SPEC-007 where determinism matters.
3. Log path: operator-chosen, any location; parent dir must exist; file created `0600`.

## Tasks
1. [x] Review/approve spec (answer open questions)
2. [x] Tests R1–R8 (red)
3. [x] Implement `audit/logger.py`, models, client + server wiring
4. [x] Ruff, README (threat-model row "Operator breach → audit trail"), commit
