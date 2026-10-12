"""Scan untrusted text (user input or retrieved documents) for prompt injection."""
from __future__ import annotations

from dataclasses import dataclass, field

from .normalize import has_hidden_chars, has_homoglyphs, views
from .rules import RULES

BLOCK_THRESHOLD = 7
WARN_THRESHOLD = 4


@dataclass
class Finding:
    rule_id: str
    category: str
    owasp: str
    severity: int
    view: str
    evidence: str
    description: str


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    risk: int = 0

    @property
    def verdict(self) -> str:
        if self.risk >= BLOCK_THRESHOLD:
            return "block"
        return "warn" if self.risk >= WARN_THRESHOLD else "allow"

    @property
    def flagged(self) -> bool:
        return self.verdict != "allow"


def scan(text: str, source: str = "user") -> ScanResult:
    """Scan ``text``. ``source='retrieved'`` raises severity: documents should never give orders."""
    res = ScanResult()
    seen: set[tuple[str, str]] = set()
    for label, body in views(text):
        for rule in RULES:
            m = rule.pattern.search(body)
            if not m or (rule.id, label) in seen:
                continue
            seen.add((rule.id, label))
            sev = rule.severity
            if label != "plain":
                sev = min(10, sev + 2)  # hiding the payload is itself suspicious
            if source == "retrieved" and rule.category in {"instruction_override", "indirect_instruction", "tool_abuse"}:
                sev = min(10, sev + 1)
            res.findings.append(Finding(rule.id, rule.category, rule.owasp, sev, label,
                                        m.group(0)[:120], rule.description))
    if has_hidden_chars(text):
        res.findings.append(Finding("PI-100", "obfuscation", "LLM01", 4, "raw",
                                    "zero-width characters", "Invisible characters present"))
    if has_homoglyphs(text):
        res.findings.append(Finding("PI-101", "obfuscation", "LLM01", 4, "raw",
                                    "mixed-script lookalikes", "Homoglyph characters present"))
    if res.findings:
        top = max(f.severity for f in res.findings)
        # corroboration: each additional distinct category adds a point
        extra = len({f.category for f in res.findings}) - 1
        res.risk = min(10, top + min(extra, 2))
    return res
