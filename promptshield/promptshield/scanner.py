from __future__ import annotations

from dataclasses import dataclass, field, asdict

from .normalize import normalize
from .rules import RULES, Rule

VERDICTS = ((70, "block"), (35, "suspicious"), (0, "clean"))


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: int
    owasp: str
    description: str
    excerpt: str
    via_decoded: bool = False


@dataclass
class ScanResult:
    score: int
    verdict: str
    findings: list[Finding] = field(default_factory=list)
    obfuscation: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"score": self.score, "verdict": self.verdict,
                "obfuscation": self.obfuscation,
                "findings": [asdict(f) for f in self.findings]}


class Scanner:
    """Scores text 0-100. Distinct rules add up (diminishing), obfuscation adds a bump."""

    def __init__(self, rules: list[Rule] | None = None):
        self.rules = rules if rules is not None else RULES

    def _match(self, text: str, decoded: bool) -> list[Finding]:
        out = []
        for rule in self.rules:
            m = rule.pattern.search(text)
            if m:
                out.append(Finding(rule.id, rule.category, rule.severity, rule.owasp,
                                   rule.description, m.group(0)[:120], decoded))
        return out

    def scan(self, text: str) -> ScanResult:
        n = normalize(text)
        findings = self._match(n.text, False)
        seen = {f.rule_id for f in findings}
        for blob in n.decoded_blobs:
            findings += [f for f in self._match(blob, True) if f.rule_id not in seen]
        sevs = sorted((f.severity for f in findings), reverse=True)
        score = 0.0
        for i, s in enumerate(sevs):
            score += s * 10 * (0.5 ** i) if i else s * 10
        # Hidden/encoded content is itself a strong signal when combined with any hit.
        if findings and n.obfuscated:
            score += 15
        if any(f.via_decoded for f in findings):
            score += 15
        score = min(100, round(score))
        verdict = next(v for threshold, v in VERDICTS if score >= threshold)
        # Invisible chars alone are noteworthy but not blocking.
        if verdict == "clean" and n.invisible_chars >= 3:
            verdict, score = "suspicious", max(score, 35)
        return ScanResult(score, verdict, findings, {
            "invisible_chars": n.invisible_chars, "homoglyphs": n.homoglyphs,
            "decoded_blobs": len(n.decoded_blobs)})
