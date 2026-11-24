"""
JWT security audit tool.

Analyzes (offline, token-only): alg=none, weak HMAC secrets (curated dictionary), header
key-injection vectors (jku/x5u/jwk/x5c/kid/crit), audience/issuer binding, expiry and
time-claim consistency, sensitive claim names, structural integrity. Never fetches anything.

Guarantees (SPEC-001 R3/R4):
- Never raises for any string input.
- Every target-derived string is reduced with ``safe_label`` before leaving this module.
- No exception text from the JWT library is ever echoed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import time
from functools import lru_cache
from importlib import resources
from typing import Any

from api_sec_mcp.models import Finding, JwtReport, RuleId, Severity, safe_label

MAX_SECRETS = 2000  # hard cap: bounded, deterministic runtime


@lru_cache(maxsize=1)
def _weak_secrets() -> tuple[str, ...]:
    text = resources.files("api_sec_mcp").joinpath("data/jwt_weak_secrets.txt").read_text("utf-8")
    entries = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
    return tuple(entries[:MAX_SECRETS])


_HMAC_DIGESTS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
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


_PENALTY = {Severity.HIGH: 30, Severity.MEDIUM: 15, Severity.LOW: 5}


def _decode_segment(segment: str) -> dict[str, Any] | None:
    """Decode a base64url JSON object without trusting or validating anything (no library quirks)."""
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        value = json.loads(raw)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _find_weak_secret(token: str, digest: Any) -> str | None:  # noqa: ANN401
    signing_input, _, sig_b64 = token.rpartition(".")
    try:
        signature = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
    except ValueError:
        return None
    msg = signing_input.encode()
    for secret in _weak_secrets():
        mac = hmac.new(secret.encode(), msg, digest).digest()
        if hmac.compare_digest(mac, signature):
            return secret
    return None


def _kid_reason(kid: object) -> str | None:
    """Closed label describing why a ``kid`` looks like an injection, or None if benign."""
    if not isinstance(kid, str):
        return "non_string"
    lowered = kid.lower()
    if "\x00" in kid or "%00" in lowered:
        return "null_byte"
    if ".." in kid:
        return "path_traversal"
    if "/" in kid or "\\" in kid:
        return "separator"
    if "'" in kid or '"' in kid:
        return "quote"
    if ";" in kid or "|" in kid:
        return "shell_metachar"
    if len(kid) > 128:
        return "too_long"
    return None


def _header_findings(header: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []

    def add(rule: RuleId, sev: Severity, name: str, desc: str, evidence: str) -> None:
        out.append(Finding(rule=rule, severity=sev, location=f"Header: {name}",
                           description=desc, evidence=evidence))

    for name in ("jku", "x5u"):
        if name in header:
            add(RuleId.JWT_REMOTE_KEY_URL, Severity.HIGH, name,
                "Header points to a remote key URL; if honored by the server it enables key injection or SSRF",
                f"header={name}")
    for name in ("jwk", "x5c"):
        if name in header:
            add(RuleId.JWT_EMBEDDED_KEY, Severity.HIGH, name,
                "Header embeds a verification key; a server that trusts it accepts forged tokens",
                f"header={name}")
    if "kid" in header:
        reason = _kid_reason(header["kid"])
        if reason is not None:
            add(RuleId.JWT_KID_INJECTION, Severity.HIGH, "kid",
                "Key identifier looks like a path traversal or injection payload", f"reason={reason}")
    if "crit" in header:
        add(RuleId.JWT_CRIT_HEADER, Severity.LOW, "crit",
            "Header declares critical extensions that the server must understand", "header=crit")
    return out


def _present(value: object) -> bool:
    if isinstance(value, str):
        return bool(value)
    return isinstance(value, list) and len(value) > 0


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

    header = _decode_segment(parts[0])
    if header is None:
        return _malformed(
            "Header is not valid base64url-encoded JSON",
            "Token Header",
            has_signature=has_signature,
            algorithm="malformed",
        )

    alg = str(header.get("alg", "none"))
    alg_label = safe_label(alg, 32)

    payload = _decode_segment(parts[1])
    if payload is None:
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

    # Check 2: weak HMAC secret (only well-known HMAC algorithms; signature checked once per secret)
    digest = _HMAC_DIGESTS.get(alg.upper())
    if digest is not None and has_signature:
        weak = _find_weak_secret(clean_token, digest)
        if weak is not None:
            score = min(score, 10)
            findings.append(
                Finding(
                    rule=RuleId.JWT_WEAK_HMAC_KEY,
                    severity=Severity.CRITICAL,
                    location="Signature",
                    description=f"JWT signature verified using a known weak dictionary secret: '{weak}'",
                    evidence=weak,
                )
            )

    # Check 2b: header key-injection vectors (never fetched or echoed)
    header_findings = _header_findings(header)
    for f in header_findings:
        score -= _PENALTY[f.severity]
    findings.extend(header_findings)

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

    # Check 3b: audience / issuer binding and time-claim consistency (clock-free where possible)
    nbf = _as_timestamp(payload.get("nbf"))
    claim_findings: list[Finding] = []
    if not _present(payload.get("aud")):
        claim_findings.append(Finding(
            rule=RuleId.JWT_MISSING_AUDIENCE, severity=Severity.LOW, location="Claim: aud",
            description="Token has no audience ('aud') claim, so it is not bound to a specific API"))
    if not isinstance(payload.get("iss"), str) or not payload.get("iss"):
        claim_findings.append(Finding(
            rule=RuleId.JWT_MISSING_ISSUER, severity=Severity.LOW, location="Claim: iss",
            description="Token has no issuer ('iss') claim"))
    if nbf is not None and nbf > now:
        claim_findings.append(Finding(
            rule=RuleId.JWT_NOT_YET_VALID, severity=Severity.LOW, location="Claim: nbf",
            description="Token is not valid yet ('nbf' is in the future)"))
    if exp is not None and iat is not None and exp <= iat:
        claim_findings.append(Finding(
            rule=RuleId.JWT_INCONSISTENT_TIMESTAMPS, severity=Severity.MEDIUM,
            location="Claims: iat/exp", description="Expiration is not after the issue time"))
    if exp is not None and nbf is not None and nbf > exp:
        claim_findings.append(Finding(
            rule=RuleId.JWT_INCONSISTENT_TIMESTAMPS, severity=Severity.MEDIUM,
            location="Claims: nbf/exp", description="'nbf' is later than the expiration time"))
    for f in claim_findings:
        score -= _PENALTY[f.severity]
    findings.extend(claim_findings)

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
