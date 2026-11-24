# Target Lab — INTENTIONALLY VULNERABLE

Deterministic vulnerable HTTP app used to exercise `api-sec-mcp` end to end. **Do not deploy it, and
never expose it beyond loopback.** It contains no real secrets (all keys are fixed and public).

- Without Docker: `uv run python -m target.run` (binds `127.0.0.1:8099`; refuses any other address)
- With Docker: `docker compose up --build` (published on `127.0.0.1:8099` only)
- Scope for it: `cp scope.lab.yaml scope.yaml`
- Expected findings per route: [`expected.json`](expected.json) (golden file used by the tests)
