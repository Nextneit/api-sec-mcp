"""
Domain models for api-sec-mcp.

Key principles enforced here:
- Closed enums for rule IDs and severities (no free text from targets).
- Bounded, sanitized evidence field (controlled max length, limited charset).
- Bounded factual outputs (HeadersReport) without raw HTTP response bodies.
"""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Severity(StrEnum):
    """Normalized finding severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleId(StrEnum):
    """Enforce closed vocabulary of rule identifiers."""

    # Security header rules
    HSTS_MISSING = "HSTS_MISSING"
    HSTS_SHORT_MAX_AGE = "HSTS_SHORT_MAX_AGE"
    CSP_MISSING = "CSP_MISSING"
    X_FRAME_OPTIONS_MISSING = "X_FRAME_OPTIONS_MISSING"
    X_CONTENT_TYPE_OPTIONS_MISSING = "X_CONTENT_TYPE_OPTIONS_MISSING"
    REFERRER_POLICY_MISSING = "REFERRER_POLICY_MISSING"
    SERVER_BANNER_LEAK = "SERVER_BANNER_LEAK"
    POWERED_BY_LEAK = "POWERED_BY_LEAK"

    # JWT audit rules
    JWT_ALG_NONE = "JWT_ALG_NONE"
    JWT_WEAK_HMAC_KEY = "JWT_WEAK_HMAC_KEY"
    JWT_NO_EXPIRY = "JWT_NO_EXPIRY"
    JWT_TOKEN_EXPIRED = "JWT_TOKEN_EXPIRED"  # noqa: S105
    JWT_EXCESSIVE_LIFETIME = "JWT_EXCESSIVE_LIFETIME"
    JWT_SENSITIVE_CLAIM_LEAK = "JWT_SENSITIVE_CLAIM_LEAK"
    JWT_MALFORMED_STRUCTURE = "JWT_MALFORMED_STRUCTURE"

    # CORS audit rules
    CORS_WILDCARD_ORIGIN = "CORS_WILDCARD_ORIGIN"
    CORS_WILDCARD_WITH_CREDENTIALS = "CORS_WILDCARD_WITH_CREDENTIALS"
    CORS_ORIGIN_REFLECTION = "CORS_ORIGIN_REFLECTION"
    CORS_REFLECTION_WITH_CREDENTIALS = "CORS_REFLECTION_WITH_CREDENTIALS"
    CORS_NULL_ORIGIN_ALLOWED = "CORS_NULL_ORIGIN_ALLOWED"
    CORS_WEAK_ORIGIN_VALIDATION = "CORS_WEAK_ORIGIN_VALIDATION"
    CORS_PREFLIGHT_PERMISSIVE = "CORS_PREFLIGHT_PERMISSIVE"

    # Generic / egress violations
    SCOPE_VIOLATION = "SCOPE_VIOLATION"
    OUTPUT_SUSPICIOUS_CONTENT = "OUTPUT_SUSPICIOUS_CONTENT"
    RESPONSE_TOO_LARGE = "RESPONSE_TOO_LARGE"


# Strict regex for evidence: alphanumeric, punctuation, max 128 chars
_SAFE_EVIDENCE_RE = re.compile(r"^[a-zA-Z0-9_\-\.\/\:\;\, \(\)\=\+\@]{1,128}$")


def sanitize_evidence(val: str | None) -> str | None:
    """
    Sanitize and truncate any target-controlled evidence value.
    Discards non-printable / control characters and limits length to 128.
    """
    if val is None:
        return None
    # Strip dangerous characters and clamp
    cleaned = "".join(c for c in val if c.isprintable() and c not in "<>\r\n\t`'\"\\")
    cleaned = cleaned.strip()[:128]
    return cleaned if cleaned else None


_UNSAFE_LABEL_CHARS_RE = re.compile(r"[^A-Za-z0-9_.:\-]")


def safe_label(val: object, max_len: int = 64) -> str:
    """
    Reduce any target-controlled identifier (claim name, alg, ...) to a strict charset
    ``[A-Za-z0-9_.:-]`` (everything else becomes ``_``), bounded to *max_len* chars.
    """
    return _UNSAFE_LABEL_CHARS_RE.sub("_", str(val)[:max_len]) or "_"


class Finding(BaseModel):
    """
    A single factual security finding formatted for swift human validation.

    Designed for pentesting teams to review immediately without ambiguity:
    - rule: Closed enum identifying the specific vulnerability check.
    - severity: Normalized severity level.
    - location: Specific parameter, header, endpoint, or token component affected.
    - description: Concise technical description.
    - evidence: Sanitized, bounded evidence extracted from the target response.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    rule: RuleId
    severity: Severity
    location: str = Field(default="", max_length=128, description="Affected component")
    description: str = Field(..., max_length=256)
    evidence: str | None = Field(default=None, max_length=128)

    @field_validator("evidence", mode="before")
    @classmethod
    def validate_and_sanitize_evidence(cls, v: str | None) -> str | None:
        return sanitize_evidence(v)


class HeadersReport(BaseModel):
    """
    Compact, structured report of security headers inspection.
    Raw response headers and bodies never leave egress.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    target_url: str = Field(..., max_length=2048)
    status_code: int = Field(..., ge=100, le=599)
    missing_headers: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    score: int = Field(..., ge=0, le=100, description="Security score from 0 to 100")


class JwtReport(BaseModel):
    """
    Structured report for JSON Web Token (JWT) security analysis.
    Claims and values are strictly bounded and sanitized.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    algorithm: str = Field(..., max_length=32)
    has_signature: bool
    is_expired: bool | None = None
    issued_at: int | None = None
    expires_at: int | None = None
    detected_claims: list[str] = Field(
        default_factory=list,
        description="List of claim keys detected in payload (keys only, not values)",
    )
    findings: list[Finding] = Field(default_factory=list)
    score: int = Field(..., ge=0, le=100, description="Security score from 0 to 100")


class CorsReport(BaseModel):
    """Structured report of CORS probing. Raw target header values never appear here."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    target_url: str = Field(..., max_length=2048)
    probes_sent: int = Field(..., ge=0)
    findings: list[Finding] = Field(default_factory=list)
    score: int = Field(..., ge=0, le=100, description="Security score from 0 to 100")
