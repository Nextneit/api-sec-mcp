# SPEC-004 — Request budget and rate limiting

Status: **implemented** (all open questions resolved with the recommendations below) · Depends on: SPEC-001, SPEC-002, SPEC-003

## Why
Today a confused or injected agent can call `audit_cors` in a loop (4 requests per call) or fire
many tools concurrently, hammering the target. That breaks the engagement's rules of engagement and
can cause a denial of service on a production system. The gateway must enforce a ceiling the agent
cannot negotiate with.

## Design decisions (challenge these during review)
- **D1 — Fail fast, never wait.** When a limit is hit the request is rejected immediately with a
  structured error; the gateway never sleeps or queues on behalf of the agent. Deterministic, no
  hung connections, and the agent decides what to do.
- **D2 — Three independent limits:** total engagement budget, per-host requests per minute,
  global concurrent in-flight requests.
- **D3 — The budget survives restarts** because the used count is recovered from the audit log
  (`EGRESS_ALLOWED` events). Restarting the server does not reset it. Deleting the log does
  (documented; same trust boundary as SPEC-002's hash chain).
- **D4 — Scope first, limits second.** Out-of-scope requests are rejected by `ScopeGuard` and
  never consume budget. Everything that reaches the network (including failed requests) consumes it.
- **D5 — Closed error vocabulary.** Errors expose only a fixed `kind` and a numeric `retry_after`,
  never target-derived text.

## Requirements

### R1 — Configuration (`ScopeConfig`, `scope.yaml`)
| field | default | validation |
|---|---|---|
| `max_requests_total` | 1000 | int > 0 |
| `max_requests_per_host_per_minute` | 60 | int > 0 |
| `max_concurrent_requests` | 4 | int > 0 |
- AC: defaults apply when omitted; `0`, negative or non-int values are rejected at load time;
  `scope.example.yaml` documents all three.

### R2 — Limiter component (`egress/rate_limit.py`)
- `RateLimiter(config, clock=time.monotonic, used=0)` (exposes read-only `used` and `inflight`); `acquire(host) -> Lease`, `Lease.release()`;
  `check_capacity(host, n) -> None` (non-reserving).
- Per-host sliding window of 60 s; hosts are tracked independently (key = lowercase hostname).
- `acquire` raises `RateLimitExceededError(kind, retry_after)` with
  `kind ∈ {TOTAL_BUDGET, HOST_RATE, CONCURRENCY}` (closed `StrEnum`).
- `retry_after` = whole seconds (ceil) until the oldest in-window request expires; `None` for `TOTAL_BUDGET`; fixed `1` for `CONCURRENCY`.
- Check order: `TOTAL_BUDGET` → `CONCURRENCY` → `HOST_RATE`; nothing is consumed when a check fails.
- AC (fake clock): 60 acquires pass, the 61st raises `HOST_RATE` with correct `retry_after`; advancing
  the clock 60 s frees capacity; two hosts do not share a window; failed acquires consume nothing.

### R3 — Total budget persisted via the audit log
- `AuditLog.count(EventType)` returns events of that type seen at open time plus those recorded since.
- `build_egress_client` seeds the limiter's used count with `audit.count(EGRESS_ALLOWED)`.
- AC: with a log already containing N `EGRESS_ALLOWED` events, only `max_requests_total − N` further
  requests are allowed after a restart; with a missing log the full budget is available.

### R4 — Concurrency cap
- The in-flight counter is incremented at acquire and decremented in a `finally`, covering success,
  error and task cancellation.
- AC: with `max_concurrent_requests=2`, a third simultaneous request (blocked in the transport) is
  rejected with `CONCURRENCY`; after the first completes (or raises, or is cancelled) a new one is accepted.

### R5 — Client integration and audit
- `EgressClient(..., limiter=...)`; order in `request()`: `ScopeGuard.check` → `limiter.acquire` →
  `EGRESS_ALLOWED` → send → `EGRESS_COMPLETED` / `EGRESS_ERROR` → release.
- New `EventType.EGRESS_RATE_LIMITED`, written BEFORE the error propagates, `reason` = the closed kind.
  Audit-or-deny from SPEC-002 still applies. If the `EGRESS_ALLOWED` write fails the lease is cancelled: slot and budget are refunded (nothing was sent).
- AC: scope violation → no budget consumed; timeout and too-large errors → budget consumed;
  rate-limited request → exactly one `EGRESS_RATE_LIMITED` event and no transport call.

### R6 — All-or-nothing multi-request tools
- `EgressClient.ensure_capacity(url, n)` calls `limiter.check_capacity(host, n)` and raises the same
  error without sending anything. `inspect_cors` calls it with `MAX_PROBES` before the first probe.
- AC: with 3 requests of budget left, `audit_cors` raises `RateLimitExceededError` and sends 0 requests.
  Documented limitation: check-only, so a concurrent caller can still exhaust capacity mid-run; in that
  case the tool fails loudly (no partial report), as in SPEC-003 R6.

### R7 — Error surface to the agent
- `RateLimitExceededError.__str__` = `Rate limit exceeded: <KIND>[; retry after <n>s]` and nothing else
  (no host, URL or counters).
- MCP tools propagate it as a tool error.
- AC: the message matches the pattern exactly for each kind, for hostile hostnames as well.

### R8 — Docs
README threat-model row ("Runaway agent / target DoS"), config block, test count; spec tasks ticked.

## Non-goals
Per-tool budgets, priority queues, waiting/backoff inside the gateway, persistent per-minute state across
restarts, distributed (multi-process) coordination, a budget-introspection tool, log-flood protection.

## Resolved questions (decisions taken)
1. **Reject vs wait (D1):** reject. Waiting hides load from the agent and risks timeouts in the MCP client.
2. **Budget from the audit log (D3):** accept it. Alternative is a separate state file, which adds a second
   thing to protect. Cost: deleting `audit.jsonl` resets the budget.
3. **Log flooding:** an agent looping on rejected calls writes one `EGRESS_RATE_LIMITED` line each time.
   Recommendation: accept for now (evidence of the loop is useful); revisit with log rotation.
4. **`get_budget` read-only tool** so the agent can plan: recommend deferring; it would also expose
   operational limits to a possibly injected agent.
5. **Defaults** (1000 / 60 per min / 4): plausible for a weekly assessment; confirm or adjust.

## Tasks
1. [x] Review/approve spec (answer open questions)
2. [x] Tests R1–R7 (red)
3. [x] Implement `egress/rate_limit.py`, `AuditLog.count`, client + server wiring, CORS capacity check
4. [x] Ruff, README, commit
