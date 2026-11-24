"""
Tests for JWT security audit tool.
"""

import time

import jwt

from api_sec_mcp.models import JwtReport, RuleId, Severity
from api_sec_mcp.tools.jwt_audit import audit_jwt


class TestJwtAuditTool:
    def test_alg_none_token_is_flagged_critical(self):
        """Token with algorithm 'none' and no signature."""
        token = jwt.encode({"sub": "user123", "role": "admin"}, key="", algorithm="none")
        report = audit_jwt(token)

        assert isinstance(report, JwtReport)
        assert report.algorithm.lower() == "none"
        assert report.has_signature is False
        assert report.score == 0

        rules = {f.rule for f in report.findings}
        assert RuleId.JWT_ALG_NONE in rules

        finding = next(f for f in report.findings if f.rule == RuleId.JWT_ALG_NONE)
        assert finding.severity == Severity.CRITICAL
        assert "Header: alg" in finding.location

    def test_missing_expiration_claim_flagged(self):
        """Valid HS256 token without 'exp' claim."""
        token = jwt.encode({"sub": "user123", "iss": "auth.example.com"}, "secret_key_123", algorithm="HS256")
        report = audit_jwt(token)

        assert report.algorithm == "HS256"
        assert report.has_signature is True
        assert report.expires_at is None

        rules = {f.rule for f in report.findings}
        assert RuleId.JWT_NO_EXPIRY in rules

        finding = next(f for f in report.findings if f.rule == RuleId.JWT_NO_EXPIRY)
        assert finding.severity == Severity.HIGH
        assert "Claim: exp" in finding.location

    def test_expired_token_detected(self):
        """Token that has already expired."""
        past_time = int(time.time()) - 3600
        token = jwt.encode(
            {"sub": "user123", "exp": past_time, "iat": past_time - 3600},
            "secret_key_123",
            algorithm="HS256",
        )
        report = audit_jwt(token)

        assert report.is_expired is True
        rules = {f.rule for f in report.findings}
        assert RuleId.JWT_TOKEN_EXPIRED in rules

    def test_excessive_lifetime_flagged(self):
        """Token with expiration > 30 days into the future."""
        now = int(time.time())
        excessive_exp = now + (35 * 86400)  # 35 days
        token = jwt.encode(
            {"sub": "user123", "iat": now, "exp": excessive_exp},
            "secret_key_123",
            algorithm="HS256",
        )
        report = audit_jwt(token)

        rules = {f.rule for f in report.findings}
        assert RuleId.JWT_EXCESSIVE_LIFETIME in rules

    def test_sensitive_claim_exposure_flagged_with_sanitized_evidence(self):
        """Token containing sensitive claims like password, api_key, credit_card."""
        now = int(time.time())
        token = jwt.encode(
            {
                "sub": "user123",
                "iat": now,
                "exp": now + 3600,
                "password_hash": "$2b$12$e8Y...malicious_or_secret",
                "secret_key": "topsecret",
            },
            "strong_secret_key_1234567890",
            algorithm="HS256",
        )
        report = audit_jwt(token)

        rules = {f.rule for f in report.findings}
        assert RuleId.JWT_SENSITIVE_CLAIM_LEAK in rules

        leak_findings = [f for f in report.findings if f.rule == RuleId.JWT_SENSITIVE_CLAIM_LEAK]
        assert len(leak_findings) == 2
        locations = {f.location for f in leak_findings}
        assert "Claim: password_hash" in locations
        assert "Claim: secret_key" in locations

    def test_weak_known_hmac_secret_flagged(self):
        """Token signed with trivial secret like 'secret', 'password', '123456'."""
        now = int(time.time())
        token = jwt.encode(
            {"sub": "user123", "iat": now, "exp": now + 3600},
            "secret",
            algorithm="HS256",
        )
        report = audit_jwt(token)

        rules = {f.rule for f in report.findings}
        assert RuleId.JWT_WEAK_HMAC_KEY in rules
        finding = next(f for f in report.findings if f.rule == RuleId.JWT_WEAK_HMAC_KEY)
        assert finding.severity == Severity.CRITICAL
        assert finding.evidence == "secret"

    def test_malformed_token_returns_graceful_report(self):
        """Malformed token string returns JWT_MALFORMED_STRUCTURE finding instead of crashing."""
        report = audit_jwt("not.a.valid.jwt.token")

        assert isinstance(report, JwtReport)
        assert report.score == 0
        rules = {f.rule for f in report.findings}
        assert RuleId.JWT_MALFORMED_STRUCTURE in rules
