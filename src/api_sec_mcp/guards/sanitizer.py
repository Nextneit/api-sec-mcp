"""
Output sanitizer guard (SPEC-006): last, heuristic layer against prompt injection.

NOT a security boundary: the boundaries are the charset/length limits and closed enums elsewhere.
This module detects instruction-like content that survived them, neutralizes it and reports it
with a closed pattern id (the matched text is never reported or logged).
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from api_sec_mcp.models import Finding, RuleId, Severity

REDACTED = "[REDACTED]"
_MAX_LEN = 256
_SKIP_PATHS = frozenset({"target_url"})  # agent input, not target content (D6)
_SEPARATORS_RE = re.compile(r"[\s_\-./\\]+")


class PatternId(StrEnum):
    IGNORE_PREVIOUS = "IGNORE_PREVIOUS"
    DISREGARD = "DISREGARD"
    NEW_INSTRUCTIONS = "NEW_INSTRUCTIONS"
    SYSTEM_PROMPT = "SYSTEM_PROMPT"
    ROLE_MARKER = "ROLE_MARKER"
    ROLE_REASSIGN = "ROLE_REASSIGN"
    TOOL_INVOCATION = "TOOL_INVOCATION"
    EXFILTRATION = "EXFILTRATION"
    CHAT_DELIMITER = "CHAT_DELIMITER"
    STRUCTURE = "STRUCTURE"


# (id, form, regex). form "norm": separators collapsed to one space; "raw": folded text as is.
_PATTERNS: tuple[tuple[PatternId, str, re.Pattern[str]], ...] = (
    (PatternId.IGNORE_PREVIOUS, "norm", re.compile(
        r"\bignore\b(?: \w+){0,3} (?:previous|prior|above|earlier|preceding|all)(?: \w+){0,2} "
        r"(?:instructions?|prompts?|rules?|messages?|context|directions?)\b")),
    (PatternId.DISREGARD, "norm", re.compile(
        r"\b(?:disregard|forget|override|bypass)\b(?: \w+){0,3} "
        r"(?:instructions?|rules?|guidelines?|polic(?:y|ies)|safety|restrictions?|system prompt)\b")),
    (PatternId.NEW_INSTRUCTIONS, "norm", re.compile(
        r"\b(?:new|updated|additional|real) instructions?\b|\bfollow (?:these|the following|my) instructions?\b")),
    (PatternId.SYSTEM_PROMPT, "norm", re.compile(
        r"\bsystem (?:prompt|message|instructions?)\b|\bdeveloper (?:prompt|message)\b")),
    (PatternId.ROLE_MARKER, "norm", re.compile(
        r"(?:^|\s)(?:system|assistant|user|human|developer)\s*:(?:\s|$)")),
    (PatternId.ROLE_REASSIGN, "norm", re.compile(
        r"\byou are (?:now|no longer|actually)\b|\bact as (?:a|an|the)\b|\bpretend (?:to be|you)\b"
        r"|\bfrom now on\b")),
    (PatternId.TOOL_INVOCATION, "norm", re.compile(
        r"\b(?:call|invoke|run|execute)(?: the| this| that| a)? (?:tool|function|command|shell|curl|api)\b"
        r"|\btool call\b|\bfunction call\b")),
    (PatternId.EXFILTRATION, "norm", re.compile(
        r"\bexfiltrat\w*|\b(?:send|post|upload|leak|forward)\b(?: \w+){0,4} "
        r"(?:api keys?|secrets?|credentials?|tokens?|passwords?)\b")),
    (PatternId.CHAT_DELIMITER, "raw", re.compile(
        r"<\||\|>|\[/?inst\]|<</?sys>>|(?:^|\n)#{3} ?(?:system|instruction|assistant|human)")),
)


def _fold(text: str) -> str:
    """NFKC + casefold, dropping format characters (zero-width etc.)."""
    folded = unicodedata.normalize("NFKC", text).casefold()
    return "".join(c for c in folded if unicodedata.category(c) != "Cf")


def scan(text: str) -> list[PatternId]:
    """Return the pattern ids found in *text*, in declaration order (deterministic)."""
    raw = _fold(text)
    norm = _SEPARATORS_RE.sub(" ", raw).strip()
    found: list[PatternId] = []
    for pid, form, rx in _PATTERNS:
        if rx.search(norm if form == "norm" else raw):
            found.append(pid)
    if (
        len(text) > _MAX_LEN
        or any(not c.isprintable() for c in text)
        or "</" in text
        or "```" in text
    ):
        found.append(PatternId.STRUCTURE)
    return found


@dataclass(frozen=True)
class Flag:
    path: str
    patterns: tuple[PatternId, ...]


@dataclass
class GuardResult:
    report: dict[str, Any]
    flags: list[Flag] = field(default_factory=list)


def apply_guard(report: dict[str, Any]) -> GuardResult:
    """Redact flagged strings and append one finding per flagged field. Input is not mutated."""
    flags: list[Flag] = []

    def walk(node: Any, path: str) -> Any:  # noqa: ANN401
        if isinstance(node, str):
            if path in _SKIP_PATHS:
                return node
            ids = scan(node)
            if ids:
                flags.append(Flag(path, tuple(ids)))
                return REDACTED
            return node
        if isinstance(node, dict):
            return {k: walk(v, f"{path}.{k}" if path else str(k)) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(v, f"{path}[{i}]") for i, v in enumerate(node)]
        return node

    clean = walk(report, "")
    if flags and isinstance(clean.get("findings"), list):
        for flag in flags:
            clean["findings"].append(
                Finding(
                    rule=RuleId.OUTPUT_SUSPICIOUS_CONTENT,
                    severity=Severity.MEDIUM,
                    location=f"Field: {flag.path}"[:128],
                    description="Target-controlled content looked like an instruction and was redacted",
                    evidence="patterns=" + ",".join(p.value for p in flag.patterns),
                ).model_dump()
            )
    return GuardResult(report=clean, flags=flags)
