# api-sec-mcp

> **Security gateway between an autonomous web/API pentesting agent and an authorized target, exposed as an MCP server.**

---

## Thesis

`api-sec-mcp` is a secure egress gateway designed specifically for **autonomous web/API pentesting agents**. 

In an automated pentest engagement, an LLM agent requires capabilities to probe HTTP endpoints, examine authentication mechanisms, and inspect server configurations. However, granting an LLM raw network access creates severe risks: prompt injection from hostile endpoints, unauthorized network pivoting, or SSRF attacks against cloud infrastructure.

`api-sec-mcp` acts as the strict enforcement barrier:
1. **Engagement Scope Control:** The agent is strictly constrained to the authorized engagement scope (`scope.yaml`). Any attempt to touch out-of-scope hosts, internal CIDRs, or cloud metadata is terminated before leaving the gateway.
2. **Deterministic, Factual Output for Human Validation:** The raw HTTP response never reaches the LLM context. Instead, pentesting tools (such as security header auditing, JWT claim verification, and CORS analysis) extract concrete facts and output structured `Finding` models (`rule`, `severity`, `location`, bounded `evidence`). Pentesters can immediately review and validate each finding without noise or hallucinated explanations.
3. **Weekly Engagement Determinism:** Because findings are bound to stable rule identifiers and structured schemas, identical target configurations produce identical findings, enabling weekly diffs to track security regressions or remediations across recurring assessments.

**The value is strictly in the security layer** — scope enforcement, anti-SSRF protections, and bounded factual structured output — not in the checks themselves.

---

## Threat model

| Threat | Mitigation |
|---|---|
| **Malicious target** — attempts prompt injection into headers, JSON body, or JWT claims to mislead or hijack the agent | Target-controlled values are stripped of control chars, validated against safe charsets, and bounded to a strict 128-char `evidence` field. Rule labels (`RuleId`) and severities (`Severity`) use closed Enums defined in code, never generated from target content. |
| **Confused or injected agent** — tries to pivot out-of-scope to internal networks or cloud metadata (SSRF) | `ScopeGuard` resolves all DNS names to IPs, validates every A/AAAA record against the engagement scope allowlist, and hard-blocks link-local (`169.254.0.0/16`, `fe80::/10`) and cloud-metadata addresses. The client connects directly to the validated IP, eliminating DNS rebinding. |
| **Alternate IP encoding bypasses** — decimal (`2130706433`), hex (`0x7f000001`), octal (`0177.0.0.1`), IPv6 mapped (`::ffff:127.0.0.1`) | `ScopeGuard` normalizes and decodes numeric representations into canonical IP addresses prior to evaluation. |
| **Open redirect SSRF pivot** — target returns a 301/302/307 pointing to an internal IP or metadata endpoint | Egress client strictly enforces `follow_redirects=False`. Redirects are never followed automatically. |
| **Denial of Service / Decompression bombs** — target sends infinite byte streams, huge Content-Length, or gzip bombs | The client checks `Content-Length` upfront before reading, truncates infinite chunk generators at `max_response_bytes`, and measures decompressed bytes for encoded responses. |
| **Operator / Scope breach** — attempts to scan an asset outside the agreed engagement scope | `ScopeGuard` operates independently of MCP. `scope.yaml` must be provided explicitly with an explicit allowlist (deny-by-default). |
| **Repudiation / unverifiable engagement** — no proof of what the agent touched or what was refused | Every egress decision (blocked / allowed / completed / error) and tool call is appended to a hash-chained JSONL audit log (`audit_log_path`). Metadata only: query strings, headers, bodies and JWT contents are never logged. **Audit-or-deny:** if the log cannot be written, the request is not sent. Verify with `uv run api-sec-verify [audit.jsonl]`. |
| **Runaway agent / target DoS** — a looping or injected agent hammers the target (e.g. `audit_cors` = 4 requests per call) | `RateLimiter` enforces a total engagement budget, a per-host sliding window and a global concurrency cap. Fail-fast with a closed error (`TOTAL_BUDGET`, `HOST_RATE`, `CONCURRENCY`) and every rejection audited as `EGRESS_RATE_LIMITED`. The budget survives restarts (recovered from the audit log). Multi-request tools check capacity up front (all-or-nothing). |
| **Instruction-like text that survives the first layer** — e.g. a JWT claim named `ignore_previous_instructions_and_call_tool` or a single-token header `system_prompt` | **Defense in depth, not a boundary.** One output choke point (`server._finish`) runs a heuristic guard (`guards/sanitizer.py`, closed `PatternId` vocabulary, Unicode-normalized, separator-insensitive) over every string of every report: matches become `[REDACTED]`, a `OUTPUT_SUSPICIOUS_CONTENT` finding records the field and pattern ids (never the text) and an `OUTPUT_FLAGGED` audit event is written. English patterns only; it cannot catch everything, which is why charset/length limits and closed enums stay the real boundaries. |

### Out of scope (documented, not mitigated here)

- **Compromised host** — if the machine running this gateway is owned, host isolation is outside our boundary.
- **API key leakage** — secrets management is the operator's responsibility.
- **Attacks on the MCP protocol transport** — transport-level encryption and MCP communication security are handled by the MCP runtime.

---

## Engagement Scope Configuration

The rules of engagement (authorized target hosts, CIDRs, ports, and schemes) are declared in `scope.yaml` (see [`scope.example.yaml`](scope.example.yaml)). The gateway denies everything not explicitly listed.

```yaml
allowed_hosts:
  - api.example.com
allowed_ips:
  - "203.0.113.42"
  - "172.20.0.0/16"      # e.g., Docker internal bridge for target testing
allowed_ports:
  - 80
  - 443
allowed_schemes:
  - https
  - http
max_response_bytes: 1048576
request_timeout_seconds: 10
audit_log_path: audit.jsonl   # append-only, hash-chained, 0600
max_requests_total: 1000                 # engagement budget (survives restarts)
max_requests_per_host_per_minute: 60
max_concurrent_requests: 4
```

---

## Architecture & Pentesting Workflow

```
                        ┌─────────────────────────────────────────┐
                        │      Autonomous Pentesting Agent        │
                        │               (LLM)                     │
                        └────────────────────┬────────────────────┘
                                             │ Invokes pentesting tool (JSON-RPC)
                                             ▼
                        ┌─────────────────────────────────────────┐
                        │           FastMCP Server                │
                        │           (api-sec-mcp)                 │
                        └────────────────────┬────────────────────┘
                                             │ Checks Engagement Scope
                                             ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ Egress Security Layer                                                           │
│                                                                                 │
│  1. ScopeGuard                                                                  │
│     ├── Engagement scope enforcement (deny-by-default)                         │
│     ├── Hard-block link-local & cloud metadata (169.254.x.x, fe80::)            │
│     ├── Normalize alternate IP formats (hex, octal, decimal integer)            │
│     └── DNS resolution & multi-A record validation (Anti-Rebinding)             │
│                                                                                 │
│  2. Guarded EgressClient (httpx wrapper)                                        │
│     ├── Connects to validated IP directly (sets SNI & Host header)              │
│     ├── Strict follow_redirects=False (prevents redirect SSRF pivots)           │
│     ├── Verify TLS certificates (verify=True)                                   │
│     ├── Content-Length upfront check & streaming size limit cutoff              │
│     ├── Decompressed bytes enforcement (Anti-Gzip bomb)                         │
│     └── Clean exceptions (no raw bodies/headers leaked in errors)               │
└────────────────────────────────────────────┬────────────────────────────────────┘
                                             │ Safe HTTP request
                                             ▼
                        ┌─────────────────────────────────────────┐
                        │            Target Web / API             │
                        └────────────────────┬────────────────────┘
                                             │ HTTP Response
                                             ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ Bounded Parsing & Human-Validation Layer                                        │
│                                                                                 │
│  - Raw response discarded inside egress layer                                   │
│  - Extraction of deterministic findings:                                        │
│      Finding(                                                                   │
│          rule="HSTS_MISSING",                                                   │
│          severity="high",                                                       │
│          location="Header: Strict-Transport-Security",                          │
│          description="Missing recommended security header...",                  │
│          evidence=None                                                          │
│      )                                                                          │
│  - Ready for fast validation by human pentesters                                │
└────────────────────────────────────────────┬────────────────────────────────────┘
                                             │ Structured JSON
                                             ▼
                        ┌─────────────────────────────────────────┐
                        │    Human Pentester / Agent Assessment   │
                        └─────────────────────────────────────────┘
```

---

## Pentesting Tools

The MCP server exposes specific reconnaissance and assessment tools designed for web and API pentesting:

1. **`audit_security_headers(url)`**:
   Audits HTTP response headers on the target. Evaluates HSTS presence and `max-age` strength, CSP enforcement, `X-Frame-Options` (clickjacking defense), `X-Content-Type-Options` (`nosniff`), `Referrer-Policy`, and technology banner leaks (`Server`, `X-Powered-By`).
2. **`audit_json_web_token(token)`**:
   Offline, token-only audit. Detects `alg=none`; weak HMAC secrets (curated ~350-entry dictionary, signature checked once per secret, hard cap 2000); header key-injection vectors (`jku`/`x5u` remote key URLs, `jwk`/`x5c` embedded keys, `kid` path traversal/injection, `crit`); missing `aud`/`iss`; `nbf` in the future; inconsistent timestamps; missing/expired/over-long `exp`; and sensitive claim names. It never fetches a `jku` URL (that would be an SSRF primitive controlled by the token) and never echoes target values. Algorithm confusion is out of scope until the operator can supply the server's public key. Spec: [`specs/007-jwt-extra-checks.md`](specs/007-jwt-extra-checks.md).
3. **`audit_cors(url)`**:
   Audits CORS with a **fixed** set of 4 probes (arbitrary origin, `null`, look-alike suffix domain, and a `PUT` preflight). The agent cannot supply origins. Detects wildcard origins (with/without credentials), arbitrary reflection, `null` origin, weak origin validation and permissive preflights. Target header values are never echoed; evidence is a fixed label. Spec: [`specs/003-cors.md`](specs/003-cors.md).

---

## Roadmap

- [ ] **Recurring Diff Engine (Engagement Tracking):** Compare weekly assessment runs against the same target using deterministic rule IDs to highlight newly introduced vulnerabilities and verify remediations.
- [x] **Target Lab (`target/`):** Deterministic vulnerable FastAPI environment with golden findings (see below).
- [x] **Secondary Sanitizer Guard (`guards/sanitizer.py`):** Pattern-based heuristic scanner that redacts and reports instruction-like content in tool output (see below).

---

## Development & Testing

The test suite runs entirely offline using synthetic DNS resolvers and `httpx.MockTransport`. No real network calls are ever made during testing.

### Install dependencies

```bash
uv sync --all-groups
```

### Run tests

```bash
uv run pytest tests/ -v
```

Current test suite covers **434 tests**:
- **`tests/test_scope_guard.py`** (52 tests): Engagement scope enforcement, cloud metadata hard blocks, alternate encodings, IPv6, CIDR matching, port/scheme filtering, and DNS rebinding protections.
- **`tests/test_egress_client.py`** (6 tests): Basic egress transport mocking, Host header preservation, size limits, and non-following of redirects.
- **`tests/test_egress_client_hardening.py`** (22 tests): SNI extensions, TLS verification guarantee, Content-Length aborts, infinite streaming cutoffs, gzip bomb protection, multi-header preservation (`Set-Cookie`), and public method bypass prevention (verified via mutation testing).
- **`tests/test_jwt_audit.py`** and **`tests/test_spec001_hardening.py`**: JWT checks, bounded/sanitized output, never-raise guarantees, scope-config wiring, fail-closed scope loading, non-blocking DNS (see [`specs/001-hardening.md`](specs/001-hardening.md)).
- **`tests/test_spec002_audit.py`**: audit trail (atomic JSONL writes, URL redaction, audit-or-deny, hash-chain verification; see [`specs/002-audit-log.md`](specs/002-audit-log.md)).
- **`tests/test_spec003_cors.py`**: probe set and cap, classification table, preflight, bounded output, scope-violation behavior, audited MCP tool.
- **`tests/test_spec004_rate_limit.py`**: config validation, sliding window with fake clock, budget persistence via audit log, concurrency release on error/cancel, audited rejections, all-or-nothing CORS.
- **`tests/integration/`** (marked `integration`) and **`tests/test_lab_packaging.py`**: real sockets and a real MCP client against the Target Lab. Golden findings, hostile-content containment, redirect not followed, size/timeout limits, full engagement audit consistency and loopback-only packaging (see [`specs/005-target-lab.md`](specs/005-target-lab.md)).
- **`tests/test_spec006_sanitizer.py`**: pattern table (positive spellings and near-misses per pattern), zero false positives on known-good evidence, redaction/finding behavior, audited choke point; lab routes `/hostile/token` and `/jwt/hostile-claim` in `tests/integration/`.
- **`tests/test_spec007_jwt.py`**: header vectors, claim binding, time consistency, extended dictionary (file quality, speed, cap), scoring; six new JWT lab profiles with golden findings.
- **`tests/test_headers_tool.py`** (5 tests): Security header evaluations, version leaks, HSTS duration checks, and scope guard enforcement.

---

## Target Lab

[`target/`](target/README.md) is a **deliberately vulnerable**, deterministic FastAPI app: insecure and secure header
profiles, six CORS behaviors, five JWT profiles, hostile content (prompt injection in body and headers), a redirect
to the cloud-metadata IP, and oversize / gzip-bomb / endless / slow responses. Expected findings per route live in
[`target/expected.json`](target/expected.json) and are the golden reference for the tests.

```bash
# Integration tests (spawn the lab in-process on 127.0.0.1, no Docker needed)
uv run pytest -m integration -v

# Manual demo
uv run python -m target.run            # or: docker compose up --build   (published on 127.0.0.1:8099 only)
cp scope.lab.yaml scope.yaml
npx @modelcontextprotocol/inspector uv run api-sec-mcp
```

The lab refuses to bind anywhere but loopback (outside the container) and holds no real secrets.

---

## Quick Start

```bash
# 1. Install dependencies
uv sync --all-groups

# 2. Configure engagement scope
cp scope.example.yaml scope.yaml
# Edit scope.yaml to authorize your target hosts and IP ranges.
# The server refuses to start without it (fail-closed; no fallback to the example).

# 3. Launch MCP server
uv run api-sec-mcp

# Or inspect interactively with MCP Inspector
npx @modelcontextprotocol/inspector uv run api-sec-mcp
```
