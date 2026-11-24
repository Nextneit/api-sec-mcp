"""
JWT security audit tool.

Analyzes: alg=none, weak HMAC secrets (small dictionary), expiry claims,
sensitive claim names, structural integrity.

Guarantees (SPEC-001 R3/R4):
- Never raises for any string input.
- Every target-derived string is reduced with ``safe_label`` before leaving this module.
- No exception text from the JWT library is ever echoed.
"""

from __future__ import annotations

import math
import time
from typing import Any

import jwt

from api_sec_mcp.models import Finding, JwtReport, RuleId, Severity, safe_label

_COMMON_WEAK_SECRETS = (
    "secret", "password", "123456", "admin", "jwt", "test",
    "app", "key", "changeme", "12345678", "default",
)
_HMAC_ALGS = frozenset({"HS256", "HS384", "HS512"})
_SENSITIVE_CLAIM_PATTERNS = frozenset({
    "password", "passwd", "pwd", "secret", "api_key", "apikey",
    "token", "private_key", "credit_card", "ssn",
})
_MAX_REASONABLE_LIFETIME = 30 * 86400
_MAX_TOKEN_LENGTH = 8192
_MAX_CLAIMS = 50
_MAX_TS = 253_402_300_799  # 9999-12-31, sanity bound for timestamps


def _as_timestamp(value: object) -> int | None:
    """Return a sane integer timestamp or None (bool/str/list/inf/nan/huge are invalid)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if not 0 <= value <= _MAX_TS:
        return None
    return int(value)


def _malformed(
    description: str,
    location: str,
    *,
    algorithm: str = "unknown",
    has_signature: bool = False,
    evidence: str | None = None,
) -> JwtReport:
    return JwtReport(
        algorithm=safe_label(algorithm, 32),
        has_signature=has_signature,
        detected_claims=[],
        findings=[
            Finding(
                rule=RuleId.JWT_MALFORMED_STRUCTURE,
                severity=Severity.HIGH,
                location=location,
                description=description,
                evidence=evidence,
            )
        ],
        score=0,
    )


def audit_jwt(token: str) -> JwtReport:
    """Perform security analysis on a JWT string without trusting any of its content."""
    clean_token = token.strip()

    if len(clean_token) > _MAX_TOKEN_LENGTH:
        return _malformed(
            f"Token exceeds maximum auditable length of {_MAX_TOKEN_LENGTH} chars",
            "Token Structure",
            evidence=f"length={len(clean_token)}",
        )

    parts = clean_token.split(".")
    if len(parts) != 3:
        return _malformed(
            "Token does not contain the standard 3 base64url parts (header.payload.signature)",
            "Token Structure",
            evidence=f"parts_count={len(parts)}",
        )

    has_signature = bool(parts[2].strip())

    try:
        header: dict[str, Any] = jwt.get_unverified_header(clean_token)
    except Exception:
        return _malformed(
            "Header is not valid base64url-encoded JSON",
            "Token Header",
            has_signature=has_signature,
            algorithm="malformed",
        )

    alg = str(header.get("alg", "none"))
    alg_label = safe_label(alg, 32)

    try:
        payload: dict[str, Any] = jwt.decode(
            clean_token, options={"verify_signature": False, "verify_exp": False}
        )
    except Exception:
        return _malformed(
            "Payload is not a valid base64url-encoded JSON object",
            "Token Payload",
            has_signature=has_signature,
            algorithm=alg,
        )

    findings: list[Finding] = []
    score = 100

    # Check 1: alg none / missing signature
    if alg.lower() == "none" or not has_signature:
        score = 0
        findings.append(
            Finding(
                rule=RuleId.JWT_ALG_NONE,
                severity=Severity.CRITICAL,
                location="Header: alg",
                description="Token algorithm is 'none' or signature is omitted; allows arbitrary token forgery",
                evidence=f"alg={alg_label}",
            )
        )

    # Check 2: weak HMAC secret (only well-known HMAC algorithms)
    if alg.upper() in _HMAC_ALGS and has_signature:
        for weak_secret in _COMMON_WEAK_SECRETS:
            try:
                jwt.decode(
                    clean_token, key=weak_secret, algorithms=[alg.upper()],
                    options={"verify_exp": False},
                )
            except jwt.PyJWTError:
                continue
            score = min(score, 10)
            findings.append(
                Finding(
                    rule=RuleId.JWT_WEAK_HMAC_KEY,
                    severity=Severity.CRITICAL,
                    location="Signature",
                    description=f"JWT signature verified using a known weak dictionary secret: '{weak_secret}'",
                    evidence=weak_secret,
                )
            )
            break

    # Check 3: expiry
    now = int(time.time())
    exp = _as_timestamp(payload.get("exp"))
    iat = _as_timestamp(payload.get("iat"))
    is_expired: bool | None = None

    if exp is None:
        score -= 25
        findings.append(
            Finding(
                rule=RuleId.JWT_NO_EXPIRY,
                severity=Severity.HIGH,
                location="Claim: exp",
                description="Token lacks a valid numeric expiration ('exp') claim, enabling indefinite replay",
                evidence=None,
            )
        )
    else:
        is_expired = exp < now
        if is_expired:
            score -= 15
            findings.append(
                Finding(
                    rule=RuleId.JWT_TOKEN_EXPIRED,
                    severity=Severity.MEDIUM,
                    location="Claim: exp",
                    description="Token is already expired",
                    evidence=f"exp={exp}",
                )
            )
        if iat is not None and exp - iat > _MAX_REASONABLE_LIFETIME:
            lifetime = exp - iat
            score -= 10
            findings.append(
                Finding(
                    rule=RuleId.JWT_EXCESSIVE_LIFETIME,
                    severity=Severity.LOW,
                    location="Claims: iat/exp",
                    description=f"Token validity window exceeds 30 days ({lifetime // 86400} days)",
                    evidence=f"lifetime_seconds={lifetime}",
                )
            )

    # Check 4: sensitive claim names (bounded, sanitized)
    claim_labels = [safe_label(k) for k in list(payload.keys())[:_MAX_CLAIMS]]
    for raw_key, label in zip(payload.keys(), claim_labels, strict=False):
        lower_key = str(raw_key).lower()
        if any(p in lower_key for p in _SENSITIVE_CLAIM_PATTERNS):
            score -= 10
            findings.append(
                Finding(
                    rule=RuleId.JWT_SENSITIVE_CLAIM_LEAK,
                    severity=Severity.MEDIUM,
                    location=f"Claim: {label}",
                    description="Payload exposes a claim whose name suggests a credential or secret",
                    evidence=f"claim_name={label}",
                )
            )

    return JwtReport(
        algorithm=alg_label,
        has_signature=has_signature,
        is_expired=is_expired,
        issued_at=iat,
        expires_at=exp,
        detected_claims=claim_labels,
        findings=findings,
        score=max(0, min(100, score)),
    )
