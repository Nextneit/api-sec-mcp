"""
CORS audit tool (SPEC-003).

Sends a FIXED set of probes (no agent-supplied origins) and classifies the replies.
Target header values are compared, never echoed: evidence/location are fixed labels.
"""

from __future__ import annotations

from urllib.parse import urlparse

from api_sec_mcp.egress.client import EgressClient, EgressResponse
from api_sec_mcp.models import CorsReport, Finding, RuleId, Severity, safe_label

MAX_PROBES = 4  # hard cap per call: 3 GET + 1 OPTIONS preflight
_EVIL_ORIGIN = "https://evil.example"
_DANGEROUS_METHODS = ("DELETE", "PATCH", "PUT")
_PENALTY = {
    Severity.CRITICAL: 40, Severity.HIGH: 30, Severity.MEDIUM: 20,
    Severity.LOW: 5, Severity.INFO: 0,
}
_ACAO = "Access-Control-Allow-Origin"
_ACAM = "Access-Control-Allow-Methods"


def _finding(rule: RuleId, severity: Severity, header: str, kind: str, creds: bool,
             description: str) -> Finding:
    return Finding(
        rule=rule,
        severity=severity,
        location=f"Header: {header} (probe: {kind})",
        description=description,
        evidence=f"probe={kind};credentials={'true' if creds else 'false'}",
    )


def _classify_get(kind: str, origin: str, resp: EgressResponse, arbitrary_reflected: bool
                  ) -> list[Finding]:
    acao = resp.headers.get("access-control-allow-origin")
    creds = resp.headers.get("access-control-allow-credentials") == "true"
    if acao is None:
        return []

    if kind == "arbitrary":
        if acao == "*":
            if creds:
                return [_finding(RuleId.CORS_WILDCARD_WITH_CREDENTIALS, Severity.MEDIUM, _ACAO,
                                 kind, creds, "Wildcard origin combined with credentials allowed")]
            return [_finding(RuleId.CORS_WILDCARD_ORIGIN, Severity.LOW, _ACAO, kind, creds,
                             "Access-Control-Allow-Origin is a wildcard")]
        if acao == origin:
            if creds:
                return [_finding(RuleId.CORS_REFLECTION_WITH_CREDENTIALS, Severity.CRITICAL,
                                 _ACAO, kind, creds,
                                 "Arbitrary Origin is reflected and credentials are allowed")]
            return [_finding(RuleId.CORS_ORIGIN_REFLECTION, Severity.MEDIUM, _ACAO, kind, creds,
                             "Arbitrary Origin is reflected in Access-Control-Allow-Origin")]
    elif kind == "null" and acao == "null":
        sev = Severity.HIGH if creds else Severity.MEDIUM
        return [_finding(RuleId.CORS_NULL_ORIGIN_ALLOWED, sev, _ACAO, kind, creds,
                         "The 'null' origin is allowed")]
    elif kind == "suffix" and acao == origin and not arbitrary_reflected:
        return [_finding(RuleId.CORS_WEAK_ORIGIN_VALIDATION, Severity.HIGH, _ACAO, kind, creds,
                         "Origin validation accepts attacker-controlled look-alike domains")]
    return []


def _classify_preflight(origin: str, resp: EgressResponse) -> list[Finding]:
    acao = resp.headers.get("access-control-allow-origin")
    if acao not in (origin, "*"):
        return []
    raw = resp.headers.get("access-control-allow-methods", "")
    tokens = {t.strip().upper() for t in raw.split(",") if t.strip()}
    matched = list(_DANGEROUS_METHODS) if "*" in tokens else [
        m for m in _DANGEROUS_METHODS if m in tokens
    ]
    if not matched:
        return []
    creds = resp.headers.get("access-control-allow-credentials") == "true"
    return [Finding(
        rule=RuleId.CORS_PREFLIGHT_PERMISSIVE,
        severity=Severity.MEDIUM,
        location=f"Header: {_ACAM} (probe: preflight)",
        description="Preflight allows state-changing methods for an untrusted origin",
        evidence=f"methods={','.join(matched)};credentials={'true' if creds else 'false'}",
    )]


async def inspect_cors(url: str, client: EgressClient) -> CorsReport:
    """Run the fixed CORS probe set against *url* through the guarded egress client."""
    await client.ensure_capacity(url, MAX_PROBES)  # all-or-nothing (SPEC-004 R6)
    parsed = urlparse(url)
    scheme = parsed.scheme if parsed.scheme in ("http", "https") else "https"
    host = safe_label(parsed.hostname or "", 253)
    suffix_origin = f"{scheme}://{host}.evil.example"

    findings: list[Finding] = []
    sent = 0

    arbitrary = await client.get(url, headers={"Origin": _EVIL_ORIGIN})
    sent += 1
    findings += _classify_get("arbitrary", _EVIL_ORIGIN, arbitrary, False)
    arbitrary_reflected = arbitrary.headers.get("access-control-allow-origin") == _EVIL_ORIGIN

    null_resp = await client.get(url, headers={"Origin": "null"})
    sent += 1
    findings += _classify_get("null", "null", null_resp, arbitrary_reflected)

    suffix_resp = await client.get(url, headers={"Origin": suffix_origin})
    sent += 1
    findings += _classify_get("suffix", suffix_origin, suffix_resp, arbitrary_reflected)

    preflight = await client.options(url, headers={
        "Origin": _EVIL_ORIGIN, "Access-Control-Request-Method": "PUT",
    })
    sent += 1
    findings += _classify_preflight(_EVIL_ORIGIN, preflight)

    score = max(0, 100 - sum(_PENALTY[f.severity] for f in findings))
    return CorsReport(target_url=url, probes_sent=sent, findings=findings, score=score)
