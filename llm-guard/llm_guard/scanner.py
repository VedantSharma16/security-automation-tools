"""Input scanner: runs every rule over every de-obfuscated view of the text."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .normalize import has_hidden_chars, views
from .rules import OBFUSCATION_ENCODED, OBFUSCATION_HIDDEN, RULES

BLOCK_THRESHOLD = 8
WARN_THRESHOLD = 5
# Untrusted retrieved content (RAG docs, web pages, emails) gets a stricter bar:
# it should never be giving the model orders in the first place.
UNTRUSTED_BONUS = 2


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: int
    description: str
    owasp: str
    view: str
    evidence: str


@dataclass
class Verdict:
    action: str  # allow | warn | block
    score: int
    findings: list[Finding] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.action == "block"

    def to_dict(self) -> dict:
        return {"action": self.action, "score": self.score, "findings": [asdict(f) for f in self.findings]}


def scan_input(text: str, source: str = "user") -> Verdict:
    """Scan text. `source` is "user" or "untrusted" (retrieved/tool content)."""
    findings: list[Finding] = []
    seen: set[str] = set()
    raw_hit = False
    decoded_hit = False

    for view_name, content in views(text):
        for rule in RULES:
            m = rule.pattern.search(content)
            if not m or rule.id in seen:
                continue
            seen.add(rule.id)
            findings.append(Finding(rule.id, rule.category, rule.severity, rule.description,
                                    rule.owasp, view_name, m.group(0)[:120]))
            if view_name == "raw":
                raw_hit = True
            else:
                decoded_hit = True

    if has_hidden_chars(text):
        rid, sev, desc = OBFUSCATION_HIDDEN
        findings.append(Finding(rid, "obfuscation", sev, desc, "LLM01", "raw", "<hidden characters>"))
    if decoded_hit and not raw_hit:
        rid, sev, desc = OBFUSCATION_ENCODED
        findings.append(Finding(rid, "obfuscation", sev, desc, "LLM01", "decoded", "<encoded payload>"))

    score = _score(findings, untrusted=(source == "untrusted"))
    action = "block" if score >= BLOCK_THRESHOLD else "warn" if score >= WARN_THRESHOLD else "allow"
    return Verdict(action, score, sorted(findings, key=lambda f: -f.severity))


def _score(findings: list[Finding], untrusted: bool) -> int:
    if not findings:
        return 0
    sevs = sorted((f.severity for f in findings), reverse=True)
    # Highest severity dominates; each additional distinct finding adds corroboration.
    score = sevs[0] + min(3, len(sevs) - 1)
    if untrusted and any(f.category != "obfuscation" for f in findings):
        score += UNTRUSTED_BONUS
    return min(score, 10)
