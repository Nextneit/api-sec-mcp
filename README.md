# api-sec-mcp

> **Security gateway between an LLM agent and an HTTP target, exposed as an MCP server.**

---

## Thesis

`api-sec-mcp` is a security gateway that sits between an LLM agent and any HTTP target.
The agent can only communicate with **explicitly authorized hosts**, and it only receives
**typed, bounded data** — never raw text or uncontrolled responses coming from the target.

The gateway is exposed as an [MCP](https://modelcontextprotocol.io/) server (via FastMCP)
and provides security-audit tools (security headers, JWT claims, CORS policy, etc.).

**The value is strictly in the security layer** — scope enforcement, anti-SSRF protections,
and bounded factual structured output — not in the checks themselves. Any response from
the target is treated as hostile input: raw HTTP responses never leave the egress layer,
parsers extract concrete facts and discard the rest, and all findings are expressed as
closed rule IDs and severity enums, never as LLM-generated prose derived from target data.

---

## Threat model

| Threat | Mitigation |
|---|---|
| **Malicious target** — attempts prompt injection into headers, JSON body, or JWT claims | Target-controlled values are stripped of control chars, validated against safe charsets, and bounded to a strict 128-char `evidence` field. Rule labels (`RuleId`) and severities (`Severity`) use closed Enums defined in code, never generated from target content. |
| **Confused or injected agent** — tries to pivot to internal networks or cloud metadata (SSRF) | `ScopeGuard` resolves all DNS names to IPs, validates every A/AAAA record against an explicit allowlist, and hard-blocks link-local (`169.254.0.0/16`, `fe80::/10`) and cloud-metadata addresses. The client connects directly to the validated IP, eliminating DNS rebinding. |
| **Alternate IP encoding bypasses** — decimal (`2130706433`), hex (`0x7f000001`), octal (`0177.0.0.1`), IPv6 mapped (`::ffff:127.0.0.1`) | `ScopeGuard` normalizes and decodes numeric representations into canonical IP addresses prior to evaluation. |
| **Open redirect SSRF pivot** — target returns a 301/302/307 pointing to an internal IP or metadata endpoint | Egress client strictly enforces `follow_redirects=False`. Redirects are never followed automatically. |
| **Denial of Service / Decompression bombs** — target sends infinite byte streams, huge Content-Length, or gzip bombs | The client checks `Content-Length` upfront before reading, truncates infinite chunk generators at `max_response_bytes`, and measures decompressed bytes for encoded responses. |
| **Careless operator** — tries to scan unauthorized targets | `ScopeGuard` operates independently of MCP. `scope.yaml` must be provided explicitly with an explicit allowlist (deny-by-default). |

### Out of scope (documented, not mitigated here)

- **Compromised host** — if the machine running this gateway is owned, host isolation is outside our boundary.
- **API key leakage** — secrets management is the operator's responsibility.
- **Attacks on the MCP protocol transport** — transport-level encryption and MCP communication security are handled by the MCP runtime.

---

## Scope configuration

Target hosts, CIDRs, ports, and schemes are declared in `scope.yaml` (see [`scope.example.yaml`](scope.example.yaml)). The gateway denies everything not explicitly listed.

```yaml
allowed_hosts:
  - api.example.com
allowed_ips:
  - "203.0.113.42"
  - "172.20.0.0/16"      # e.g., Docker internal bridge
allowed_ports:
  - 80
  - 443
allowed_schemes:
  - https
  - http
max_response_bytes: 1048576
request_timeout_seconds: 10
```

---

## Architecture & Security Controls

```
                        ┌────────────────────────┐
                        │       LLM Agent        │
                        └───────────┬────────────┘
                                    │ MCP Tools (JSON-RPC)
                                    ▼
                        ┌────────────────────────┐
                        │   FastMCP Server       │
                        │   (src/api_sec_mcp)    │
                        └───────────┬────────────┘
                                    │ Typed parameters
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Egress Security Layer                                                  │
│                                                                        │
│  1. ScopeGuard                                                         │
│     ├── Deny-by-default policy check                                   │
│     ├── Hard-block link-local & cloud metadata (169.254.x.x, fe80::)   │
│     ├── Normalize alternate IP formats (hex, octal, decimal integer)   │
│     └── DNS resolution & multi-A record validation (Anti-Rebinding)    │
│                                                                        │
│  2. Guarded EgressClient (httpx wrapper)                               │
│     ├── Connects to validated IP directly (sets SNI & Host header)     │
│     ├── Strict follow_redirects=False                                  │
│     ├── Verify TLS certificates (verify=True)                          │
│     ├── Content-Length upfront check & streaming size limit cutoff     │
│     ├── Decompressed bytes enforcement (Anti-Gzip bomb)                │
│     └── Clean exceptions (no raw bodies/headers leaked in errors)      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Safe HTTP request
                                    ▼
                        ┌────────────────────────┐
                        │      HTTP Target       │
                        └────────────────────────┘
```

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

Current test suite covers **80 tests** across:
- **`tests/test_scope_guard.py`** (52 tests): SSRF, cloud metadata hard blocks, alternate encodings, IPv6, CIDR matching, port/scheme filtering, and DNS rebinding protections.
- **`tests/test_egress_client.py`** (6 tests): Basic egress transport mocking, Host header preservation, size limits, and non-following of redirects.
- **`tests/test_egress_client_hardening.py`** (22 tests): SNI extensions, TLS verification guarantee, Content-Length aborts, infinite streaming cutoffs, gzip bomb protection, multi-header preservation (`Set-Cookie`), and public method bypass prevention (verified via mutation testing).

---

## Project layout

```
src/api_sec_mcp/
├── server.py             # FastMCP app — registers tools only
├── models.py             # Finding, HeadersReport (Pydantic v2 domain models)
├── egress/
│   ├── scope_guard.py    # Allowlist & SSRF defense (standalone library)
│   └── client.py         # Hardened httpx client wrapper
├── guards/
│   └── sanitizer.py      # Secondary pattern-based sanitizer (alerts only)
├── tools/
│   ├── headers.py        # inspect_security_headers tool
│   ├── jwt_audit.py      # inspect_jwt tool
│   └── cors.py           # inspect_cors tool
└── audit/
    └── log.py            # Structured audit logging
```
