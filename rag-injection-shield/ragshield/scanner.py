"""Core scanning: normalise text, apply rules, score risk."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict

from .normalize import normalize
from .rules import RULES

# Verdict thresholds on the 0-100 risk score.
BLOCK_AT = 70
QUARANTINE_AT = 30

EVASION_BONUS = 10  # added per distinct evasion technique observed


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: int
    description: str
    start: int
    end: int
    excerpt: str
    source: str = "text"  # text | base64 | html-comment


@dataclass
class ScanResult:
    score: int
    verdict: str  # allow | quarantine | block
    findings: list[Finding] = field(default_factory=list)
    evasions: list[str] = field(default_factory=list)
    normalized: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("normalized")
        return d


def _excerpt(text: str, s: int, e: int, pad: int = 20) -> str:
    return text[max(0, s - pad): min(len(text), e + pad)].replace("\n", " ").strip()


def _apply_rules(text: str, source: str) -> list[Finding]:
    found = []
    for rule in RULES:
        for m in rule.pattern.finditer(text):
            found.append(Finding(rule.id, rule.category, rule.severity, rule.description,
                                 m.start(), m.end(), _excerpt(text, m.start(), m.end()), source))
    return found


def score(findings: list[Finding], evasions: list[str]) -> int:
    """Diminishing-returns scoring: top finding dominates, extras add less."""
    if not findings and not evasions:
        return 0
    sevs = sorted((f.severity for f in findings), reverse=True)
    total = 0.0
    for i, sev in enumerate(sevs):
        total += sev * 10 * (0.5 ** i)
    # Instructions inside hidden channels (decoded blobs / comments) are worse.
    if any(f.source != "text" for f in findings):
        total += 15
    # Evasion on its own is mildly suspicious; combined with a hit it's damning.
    total += EVASION_BONUS * len(evasions) * (2 if findings else 1)
    return int(min(100, round(total)))


def verdict_for(s: int) -> str:
    return "block" if s >= BLOCK_AT else "quarantine" if s >= QUARANTINE_AT else "allow"


def scan_text(text: str) -> ScanResult:
    norm = normalize(text)
    findings = _apply_rules(norm.text, "text")
    for blob in norm.decoded_blobs:
        findings += _apply_rules(blob, "base64")
    for f in findings:  # tag text hits that sit inside an HTML comment (hidden channel)
        if f.source == "text" and any(a <= f.start < b for a, b in norm.comment_spans):
            f.source = "html-comment"
    s = score(findings, norm.evasions)
    return ScanResult(s, verdict_for(s), findings, norm.evasions, norm.text)
