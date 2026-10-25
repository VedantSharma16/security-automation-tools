"""Layered scan: normalize, decode, run rules, combine into a risk verdict."""

from __future__ import annotations

from dataclasses import dataclass, field

from .normalize import decode_base64_blobs, had_obfuscation, normalize
from .rules import RULES, Rule

BLOCK_THRESHOLD = 0.8
SUSPICIOUS_THRESHOLD = 0.5

OBFUSCATION_RULE = Rule("OBF-001", "obfuscation", 4,
                        "Invisible characters or mixed-script look-alikes used to evade filters", None)  # type: ignore[arg-type]
ENCODED_RULE_SEVERITY_BONUS = 1  # payloads hidden in base64 are rated slightly higher


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    severity: int
    description: str
    evidence: str
    source: str = "input"  # "input" or "base64"


@dataclass
class Verdict:
    label: str  # allow | suspicious | block
    score: float
    findings: list[Finding] = field(default_factory=list)

    @property
    def categories(self) -> list[str]:
        return sorted({f.category for f in self.findings})

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "score": round(self.score, 3),
            "categories": self.categories,
            "findings": [vars(f) for f in self.findings],
        }


def _run_rules(text: str, source: str) -> list[Finding]:
    found = []
    for rule in RULES:
        m = rule.pattern.search(text)
        if m:
            sev = min(10, rule.severity + (ENCODED_RULE_SEVERITY_BONUS if source == "base64" else 0))
            found.append(Finding(rule.id, rule.category, sev, rule.description, m.group(0).strip()[:120], source))
    return found


def combine(findings: list[Finding]) -> float:
    """Noisy-OR: independent signals compound but never exceed 1.0."""
    miss = 1.0
    for f in findings:
        miss *= 1 - f.severity / 10
    return 1 - miss


def label_for(score: float) -> str:
    if score >= BLOCK_THRESHOLD:
        return "block"
    if score >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "allow"


def scan(text: str) -> Verdict:
    findings = _run_rules(normalize(text), "input")
    for blob in decode_base64_blobs(text):
        findings.extend(_run_rules(normalize(blob), "base64"))
    if had_obfuscation(text):
        findings.append(Finding(OBFUSCATION_RULE.id, OBFUSCATION_RULE.category, OBFUSCATION_RULE.severity,
                                OBFUSCATION_RULE.description, "(non-printing / look-alike characters)"))
    # Dedupe by rule id, keeping the highest severity (base64 hit beats plain hit).
    best: dict[str, Finding] = {}
    for f in findings:
        if f.rule_id not in best or f.severity > best[f.rule_id].severity:
            best[f.rule_id] = f
    final = sorted(best.values(), key=lambda f: -f.severity)
    score = combine(final)
    return Verdict(label_for(score), score, final)
