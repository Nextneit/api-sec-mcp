# api-sec-mcp

> **Security gateway between an LLM agent and an HTTP target, exposed as an MCP server.**

---

## Thesis

`api-sec-mcp` is a security gateway that sits between an LLM agent and any HTTP target.
The agent can only communicate with **explicitly authorized hosts**, and it only receives
**typed, bounded data** — never raw text coming from the target.

The gateway is exposed as an [MCP](https://modelcontextprotocol.io/) server (via FastMCP)
and provides security-audit tools (security headers, JWT claims, CORS policy, …).

**The value is in the security layer** — scope enforcement + structured output — not in the
checks themselves. Any response from the target is treated as hostile input: raw HTTP
responses never leave the egress layer, parsers extract concrete facts and discard the
rest, and all findings are expressed as typed rule IDs and severity enums, never as LLM-
generated prose derived from target data.

---

## Threat model

| Threat | Mitigation |
|---|---|
| **Malicious target** — injects instructions into headers, JSON body, or JWT claims | All target-controlled values are sanitized (strict regex, max length, limited charset) before being placed in a bounded `evidence` field. Rule labels and severity levels come from our own code, never from the target. |
| **Confused or injected agent** — tries to pivot to internal IPs or cloud metadata endpoints (SSRF) | `ScopeGuard` resolves all DNS names to IPs, validates every A/AAAA record against an explicit allowlist (host names + CIDR ranges), and blocks link-local (`169.254.0.0/16`), loopback, and cloud-metadata addresses by default. The validated IP — not the original hostname — is passed to the HTTP client, preventing DNS rebinding. |
| **Careless operator** — tries to scan an unauthorized target | `ScopeGuard` enforces the allowlist at the library level, independently of the MCP layer. `scope.yaml` must be provided explicitly; there is no permissive default. |

### Out of scope (documented, not mitigated here)

- **Compromised host** — if the machine running this server is owned, all bets are off.
- **API key leakage** — secrets management is the operator's responsibility.
- **Attacks on the MCP protocol itself** — transport-level security is handled by the MCP runtime.

---

## Scope configuration

Target hosts, CIDRs, ports, and schemes are declared in `scope.yaml` (see
[`scope.example.yaml`](scope.example.yaml)). The gateway denies everything not explicitly
listed.

---

## Quick start

```bash
uv sync --group dev
cp scope.example.yaml scope.yaml
# edit scope.yaml to authorize your target
uv run api-sec-mcp
```

---

## Project layout

```
src/api_sec_mcp/
├── server.py           # FastMCP app — registers tools only
├── models.py           # Finding, HeadersReport (Pydantic v2)
├── egress/
│   ├── scope_guard.py  # Allowlist enforcement (standalone library)
│   └── client.py       # httpx wrapper — always calls ScopeGuard first
├── guards/
│   └── sanitizer.py    # Secondary pattern-based sanitizer (alerts only)
├── tools/
│   ├── headers.py      # inspect_security_headers tool
│   ├── jwt_audit.py    # inspect_jwt tool
│   └── cors.py         # inspect_cors tool
└── audit/
    └── log.py          # Structured audit logging
```
