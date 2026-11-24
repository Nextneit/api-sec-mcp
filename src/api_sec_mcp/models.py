"""
Domain models for api-sec-mcp.

Key principles enforced here:
- Closed enums for rule IDs and severities (no free text from targets).
- Bounded, sanitized evidence field (controlled max length, limited charset).
- Bounded factual outputs (HeadersReport) without raw HTTP response bodies.
"""

from __future__ import annotations

from enum import StrEnum
import re
from typing import Annotated

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

    # Generic / egress violations
    SCOPE_VIOLATION = "SCOPE_VIOLATION"
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


class Finding(BaseModel):
    """A single security audit finding."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rule: RuleId
    severity: Severity
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
