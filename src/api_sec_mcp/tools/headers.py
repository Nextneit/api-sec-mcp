"""
Security headers inspection tool.

Evaluates:
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Version banner leaks (Server, X-Powered-By)

Outputs strictly typed HeadersReport. Raw HTTP response is discarded.
"""

from __future__ import annotations

import re

from api_sec_mcp.egress.client import EgressClient
from api_sec_mcp.models import Finding, HeadersReport, RuleId, Severity

# A banner is reduced to a single ``product[/version]`` token so target text never reaches the report.
_BANNER_RE = re.compile(
    r"^([A-Za-z][A-Za-z0-9_.\-]{0,31})(?![A-Za-z0-9_.\-])(?:/([0-9][A-Za-z0-9._\-]{0,15})(?![A-Za-z0-9._\-]))?"
)


def _banner_evidence(value: str) -> str:
    match = _BANNER_RE.match(value.strip())
    if not match:
        return "unrecognized"
    return match.group(1) + (f"/{match.group(2)}" if match.group(2) else "")


# Recommended headers and weights for score computation (100 max)
_RECOMMENDED_HEADERS = {
    "strict-transport-security": ("Strict-Transport-Security", 25, RuleId.HSTS_MISSING, Severity.HIGH),
    "content-security-policy": ("Content-Security-Policy", 25, RuleId.CSP_MISSING, Severity.HIGH),
    "x-frame-options": ("X-Frame-Options", 20, RuleId.X_FRAME_OPTIONS_MISSING, Severity.MEDIUM),
    "x-content-type-options": ("X-Content-Type-Options", 15, RuleId.X_CONTENT_TYPE_OPTIONS_MISSING, Severity.MEDIUM),
    "referrer-policy": ("Referrer-Policy", 15, RuleId.REFERRER_POLICY_MISSING, Severity.LOW),
}


async def inspect_security_headers(
    url: str,
    client: EgressClient,
) -> HeadersReport:
    """
    Perform safe HTTP GET request through EgressClient and audit security headers.
    """
    response = await client.get(url)

    missing_headers: list[str] = []
    findings: list[Finding] = []
    score = 100

    headers = response.headers

    # 1. Audit missing essential security headers
    for lower_key, (canon_name, weight, rule_id, severity) in _RECOMMENDED_HEADERS.items():
        if lower_key not in headers or not headers[lower_key].strip():
            missing_headers.append(canon_name)
            score -= weight
            findings.append(
                Finding(
                    rule=rule_id,
                    severity=severity,
                    location=f"Header: {canon_name}",
                    description=f"Missing recommended security header: {canon_name}",
                    evidence=None,
                )
            )

    # 2. Audit HSTS max-age if present
    hsts_val = headers.get("strict-transport-security")
    if hsts_val:
        match = re.search(r"max-age=(\d+)", hsts_val, re.IGNORECASE)
        if match:
            max_age = int(match.group(1))
            # Less than 6 months (15768000 seconds) is considered short
            if max_age < 15768000:
                score = max(0, score - 10)
                findings.append(
                    Finding(
                        rule=RuleId.HSTS_SHORT_MAX_AGE,
                        severity=Severity.LOW,
                        location="Header: Strict-Transport-Security (max-age directive)",
                        description="HSTS max-age is shorter than recommended 6 months (15768000s)",
                        evidence=f"max-age={max_age}",
                    )
                )

    # 3. Audit version leak headers
    server_banner = headers.get("server")
    if server_banner:
        # Penalize if it leaks detailed server version (e.g. Apache/2.4.41 or contains digits)
        if any(c.isdigit() for c in server_banner):
            score = max(0, score - 5)
            findings.append(
                Finding(
                    rule=RuleId.SERVER_BANNER_LEAK,
                    severity=Severity.LOW,
                    location="Header: Server",
                    description="Server header exposes specific product version banner",
                    evidence=_banner_evidence(server_banner),
                )
            )

    powered_by = headers.get("x-powered-by")
    if powered_by:
        score = max(0, score - 5)
        findings.append(
            Finding(
                rule=RuleId.POWERED_BY_LEAK,
                severity=Severity.LOW,
                location="Header: X-Powered-By",
                description="X-Powered-By header leaks server-side technology details",
                evidence=_banner_evidence(powered_by),
            )
        )

    # Clamp score between 0 and 100
    final_score = max(0, min(100, score))

    return HeadersReport(
        target_url=url,
        status_code=response.status_code,
        missing_headers=missing_headers,
        findings=findings,
        score=final_score,
    )
