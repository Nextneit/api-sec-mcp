# SPEC-005 — Target Lab and end-to-end integration tests

Status: **implemented** (all open questions resolved with the recommendations below) · Depends on: SPEC-001…004

> Renumbering note: the lab moves ahead of the diff engine (previously 007/008). Roadmap order is now
> 005 Target Lab → 006 Sanitizer guard → 007 JWT extra checks → 008 Diff engine.

## Why
Every guarantee so far is proven with mocks (`httpx.MockTransport`, fake resolvers). Nothing proves the
real stack works against a real HTTP server, or that a hostile target cannot reach the agent through the
real MCP protocol. We also need stable, deterministic findings to build the weekly diff engine on.

## Design decisions (challenge these during review)
- **D1 — One intentionally vulnerable FastAPI app** (`target/app.py`) with a fixed route per scenario;
  deterministic (no randomness, no clock-dependent output, fixed JWT secrets/keys).
- **D2 — Runs two ways:** in-process on an ephemeral `127.0.0.1` port for tests (no Docker needed), and via
  `docker compose` for manual demos. Same app, same scenarios.
- **D3 — Golden file:** the expected findings for every scenario live in one `target/expected.json`
  (rule, severity, location only; no timestamps, no scores). Tests compare against them; later the diff engine
  reuses them as its fixtures.
- **D4 — Tests go through the real MCP protocol** (`fastmcp.Client(mcp)`), not by calling functions, so the
  tool registration, serialization and error surface are covered.
- **D5 — Safe by construction:** the lab binds to `127.0.0.1` only (compose publishes `127.0.0.1:8099`),
  carries a visible "intentionally vulnerable" banner, and contains no real secrets.
- **D6 — Lean core:** FastAPI/uvicorn live in the `dev` dependency group; they are never imported by `src/`.

## Requirements

### R1 — Lab app and scenarios (`target/app.py`)
| route | behavior | tool it exercises |
|---|---|---|
| `/headers/insecure` | CSP, X-Frame-Options, nosniff, Referrer-Policy absent; `Server: Apache/2.4.41`; `X-Powered-By: PHP/7.4`; HSTS `max-age=3600` | headers |
| `/headers/secure` | all headers present, strong HSTS, no banners | headers |
| `/cors/reflect` | reflects any `Origin` + credentials `true` | cors |
| `/cors/wildcard` | `*`, no credentials | cors |
| `/cors/null` | allows `null` origin with credentials | cors |
| `/cors/suffix` | accepts any origin ending in `.evil.example` | cors |
| `/cors/preflight` | preflight allows `PUT, DELETE` for any origin | cors |
| `/cors/secure` | exact allowlist, no reflection | cors |
| `/jwt/{profile}` | returns `{"token": ...}` (fixed secrets, `exp` fixed in 2100 so output never depends on the clock): `weak-secret`, `alg-none`, `no-exp`, `sensitive-claim`, `secure` | jwt |
| `/hostile/body`, `/hostile/headers` | prompt-injection text in body, header values and a 500-char header | all |
| `/redirect/metadata` | `302` to `http://169.254.169.254/latest/meta-data/` | egress |
| `/limits/big`, `/limits/gzip-bomb`, `/limits/infinite`, `/limits/slow` | oversize body, decompression bomb, endless stream, 30 s delay | egress |
- AC: each route returns the same bytes/headers on every call (determinism test calls each twice).

### R2 — Packaging
- `target/Dockerfile`, `docker-compose.yml` (service `lab`, `127.0.0.1:8099:8099`, no other ports),
  `scope.lab.yaml` authorizing `127.0.0.1:8099` only, `target/README.md` with the banner.
- `pyproject`: `fastapi` and `uvicorn` added to the `dev` group.
- The lab refuses to start when `LAB_BIND` is not loopback, unless `LAB_CONTAINER=1` (set only in the
  Dockerfile, where the host-side publish is what restricts exposure).
- AC: a test asserts the compose file publishes only `127.0.0.1:8099`, and tests cover `resolve_bind`.

### R3 — Test harness (`tests/integration/conftest.py`)
- Session fixture starts uvicorn on `127.0.0.1:0` in a background thread, waits for readiness, and
  yields the base URL; teardown always stops it.
- Fixture builds a scope that authorizes only that host:port, a fresh audit log in `tmp_path`, and patches
  `server._CLIENT` so tools run for real (real resolver, real sockets).
- Integration tests are marked `@pytest.mark.integration`; no external network is ever used.
- AC: the whole integration suite runs in under 30 s and leaves no stray process or port.

### R4 — Headers & CORS golden tests
- For every route above with an expected finding set, the tool output through `fastmcp.Client` matches
  `target/expected.json` (rule + severity + location, order-insensitive).
- `/headers/secure` and `/cors/secure` produce zero findings and score 100.
- AC: changing a rule's severity or a location string makes the matching golden test fail.

### R5 — JWT golden tests
- Each `/jwt/{profile}` token, fetched by the test with a plain `httpx` call, is passed to
  `audit_json_web_token`; findings match the golden files (`weak-secret` → `JWT_WEAK_HMAC_KEY`, etc.).
- AC: `secure` yields zero findings.

### R6 — Hostile-target containment (end to end)
- Calling the headers and CORS tools on `/hostile/*` returns reports containing none of the injection
  phrases and no value longer than 128 chars in any evidence field.
- **Design change found while writing this spec:** the headers tool used to copy the raw `Server` /
  `X-Powered-By` value (up to 128 chars) into `evidence`. Banner evidence is now restricted to a single
  `product[/version]` token (`[A-Za-z][A-Za-z0-9_.-]{0,31}(/[0-9][A-Za-z0-9._-]{0,15})?`) or the literal
  `unrecognized`. Residual risk: a ≤32-char single-token header value is still echoed (covered by SPEC-006).
- `/redirect/metadata`: the redirect is not followed (the response is treated as a plain 302 and the
  audit log shows exactly one allowed request, none to `169.254.169.254`).
- AC: grep of the serialized MCP response and of `audit.jsonl` finds none of the hostile markers.

### R7 — Egress limits against real sockets
- `/limits/big`, `/limits/gzip-bomb`, `/limits/infinite` → `ResponseTooLargeError` surfaced as a tool error and
  `EGRESS_ERROR` audited with reason `ResponseTooLargeError` (`big` is rejected from Content-Length without reading).
- `/limits/slow` with `request_timeout_seconds: 1` → `EgressTimeoutError` in ≈1 s (< 3 s).
- AC: each scenario is a test; the infinite stream and the bomb are cut at the limit, not at the timeout
  (elapsed time well below `request_timeout_seconds`). Memory is not asserted: the lab runs in the same process.

### R8 — System properties after a full run
- After running every scenario through MCP: `verify_chain` is `ok`; the number of `EGRESS_ALLOWED` events
  equals the limiter's `used`; a deliberately low `max_requests_total` produces `TOTAL_BUDGET` rejections
  that also appear in the log; scope-violating URLs (`localhost` name not listed, other port) never
  reach the lab (server-side request counter unchanged).
- Requests reaching the lab are counted by an ASGI middleware owned by the test harness (no test-only routes
  in the lab).
- AC: all of the above asserted in one `test_full_engagement` scenario.

### R9 — Docs
README: "Target Lab" section (how to run with docker and without, how to run integration tests),
roadmap ticked, test count updated; `CLAUDE.md` mentions `uv run pytest -m integration`.

## Non-goals
Vulnerable behaviors not covered by an existing tool, TLS in the lab (HTTPS/SNI stays covered by mocks),
CI pipeline, performance benchmarks, multi-container topologies, real cloud-metadata emulation.

## Resolved questions (decisions taken)
1. **FastAPI/uvicorn in `dev` group** (recommended) vs a separate `lab` group: `dev` keeps
   `uv sync --all-groups` working as documented and avoids silently skipped integration tests.
2. **Integration tests in the default `pytest` run** (recommended, they are fast and offline) vs opt-in
   with `-m integration`. Default-on prevents the suite from rotting.
3. **Golden files hold rule + severity + location only** (recommended): stable across scoring tweaks.
4. **HTTPS in the lab:** defer; certificates and SNI against a self-signed cert would require relaxing
   `verify`, which we deliberately do not offer.
5. **`/_stats` endpoint** vs counting through a wrapping ASGI middleware kept in the test harness.
   Recommended: middleware in the harness, so the lab app itself has no test-only routes. (R8 then
   reads the counter from the harness instead of an HTTP route.)

## Tasks
1. [x] Review/approve spec (answer open questions)
2. [x] Lab app + golden files + harness (tests first: R4–R8 red against an empty app)
3. [x] Packaging (Dockerfile, compose, `scope.lab.yaml`) and R2 tests
4. [x] Ruff, README, CLAUDE.md, commit
