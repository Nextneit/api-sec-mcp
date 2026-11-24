# SPEC-007 — Additional JWT checks

Status: **approved** (all open questions resolved with the recommendations below) · Depends on: SPEC-001, SPEC-005 (lab), SPEC-006 (guard sits on top)

## Why
`audit_json_web_token` covers `alg=none`, a tiny weak-secret list, expiry and sensitive claim names. Real
assessments also look at the **header** (key-injection vectors that cause SSRF or forged-key acceptance), at
claims that bind a token to its audience and issuer, at time-claim consistency, and at a larger weak-secret
dictionary. All of these can be decided from the token alone, offline.

## Design decisions (challenge these during review)
- **D1 — Offline and token-only.** The tool keeps its signature `audit_json_web_token(token)`; it never fetches
  a `jku`/`x5u` URL (that would be an SSRF primitive controlled by the token). It only reports that it exists.
- **D2 — Never raise, never echo.** Same guarantees as SPEC-001: bounded labels, no library exception text,
  every target-derived value reduced with `safe_label`, closed rule enum.
- **D3 — Dictionary as data, with a hard cap.** Weak secrets move to a bundled text file loaded once;
  at most `MAX_SECRETS = 2000` entries are tried, in file order, so runtime is bounded and deterministic.
- **D4 — Time checks are clock-relative only where unavoidable.** `exp`/`nbf` comparisons use `now`, exactly as
  today; consistency checks (`exp <= iat`, `nbf > exp`) are clock-free.
- **D5 — Severities reflect exploitability** (header injection > missing audience), and new rules are `LOW`
  where they are hardening advice, so scores of existing profiles do not move more than necessary.

## Requirements

### R1 — Header-injection vectors (`tools/jwt_audit.py`)
| condition | rule | severity |
|---|---|---|
| header has `jku` or `x5u` | `JWT_REMOTE_KEY_URL` | HIGH |
| header has `jwk` or `x5c` | `JWT_EMBEDDED_KEY` | HIGH |
| `kid` contains path traversal (`..`), a separator (`/`, `\`), a quote, `;`, `\|`, `%00`, or exceeds 128 chars | `JWT_KID_INJECTION` | HIGH |
| header has `crit` | `JWT_CRIT_HEADER` | LOW |
- Evidence is a fixed label (`header=jku`, `reason=path_traversal`); the URL, key material and kid value are
  never echoed.
- AC: one parametrized case per row plus benign controls (`kid="key-2024-01"` is clean); hostile values
  (500-char kid, injection text in `jku`) produce a report with no `ValidationError` and none of the text.

### R2 — Claim binding and time consistency
| condition | rule | severity |
|---|---|---|
| no `aud` | `JWT_MISSING_AUDIENCE` | LOW |
| no `iss` | `JWT_MISSING_ISSUER` | LOW |
| `nbf` in the future | `JWT_NOT_YET_VALID` | LOW |
| `exp <= iat` or `nbf > exp` | `JWT_INCONSISTENT_TIMESTAMPS` | MEDIUM |
- Timestamps are validated exactly as today (`_as_timestamp`); invalid values count as absent.
- AC: each row, plus tokens with non-numeric `nbf`/`aud`/`iss` (list, dict, bool, inf) never raising;
  `aud` as a non-empty string or list counts as present, empty string/list as absent.

### R3 — Larger weak-secret dictionary
- `src/api_sec_mcp/data/jwt_weak_secrets.txt`: one secret per line, `#` comments allowed, deduplicated, ≤ 2000
  entries, loaded once at import. The current 11 secrets stay at the top (order preserved).
- Packaged with the wheel (`pyproject` include) and loaded through `importlib.resources`.
- AC: a token signed with a secret that is only in the new part of the list is detected (`JWT_WEAK_HMAC_KEY`);
  a strong secret is not; a test asserts the file has no duplicates, no entry longer than 64 chars and
  ≤ `MAX_SECRETS` lines; auditing a 8 KB token against the full list finishes in under 1 s.

### R4 — Scoring
- Penalties: HIGH −30, MEDIUM −15 (existing −10..−25 values unchanged), LOW −5; floor 0; `alg=none` and weak
  key keep their current caps.
- AC: existing unit and golden scores for the old profiles do not change except where the lab tokens are
  updated (see R5); a token with all four header vectors scores ≤ 10.

### R5 — Lab profiles and golden files
- Existing lab tokens gain `iss` and `aud` so their golden findings stay exactly as in SPEC-005.
- New profiles: `kid-injection`, `jku`, `embedded-jwk`, `no-aud-iss`, `nbf-future`, `weak-secret-extended`.
- `target/expected.json` gains one entry per profile with its exact expected findings; `secure` stays empty.
- AC: all lab profiles pass through the real MCP client with golden-file comparison.

### R6 — Docs
README tool description and rule list, `CLAUDE.md` note about adding rules (update `target/expected.json`),
test count, spec ticked.

## Non-goals
Fetching remote keys, verifying RS/ES signatures, algorithm-confusion testing (needs the server's public key,
not available offline), JWE tokens, JWKS endpoint auditing, token generation or forging helpers (the tool
only inspects).

## Resolved questions (decisions taken)
1. **Missing `aud`/`iss` as LOW** — recommended; they are hardening advice and many internal APIs omit them.
2. **Dictionary source:** author a curated list of widely known default/weak secrets rather than importing a
   third-party list wholesale (license and size control). Recommended.
3. **`kid` rules are heuristic** and may miss encodings; documented as such. A match is HIGH because the
   consequence (file read / injection in the key lookup) is severe.
4. **Algorithm-confusion** stays out of scope until a spec defines how the operator supplies the public key
   (it would be operator input, never agent input).

## Tasks
1. [x] Review/approve spec (answer open questions)
2. [ ] Tests R1–R5 (red), update lab tokens and golden file
3. [ ] Implement rules, dictionary loader, scoring, lab profiles
4. [ ] Ruff, README, CLAUDE.md, commit
