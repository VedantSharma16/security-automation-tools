"""Input scanner: combines rule hits, evasion signals, and source trust into a verdict."""
from __future__ import annotations

from dataclasses import dataclass, field

from .normalize import count_invisible, decode_base64_blobs, normalize
from .rules import RULES, Rule

# Retrieved/third-party content should never carry instructions, so it is scored harder.
SOURCE_MULTIPLIER = {"user": 1.0, "retrieved": 1.5, "tool": 1.5}
BLOCK_AT = 8.0
REVIEW_AT = 4.0


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: int
    description: str
    excerpt: str
    owasp: str = "LLM01"
    via: str = "plain"   # plain | normalized | base64


@dataclass
class ScanResult:
    score: float
    verdict: str                      # allow | review | block
    source: str
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score, "verdict": self.verdict, "source": self.source,
            "findings": [f.__dict__ for f in self.findings],
        }


def _excerpt(text: str, span: tuple[int, int], pad: int = 20) -> str:
    s, e = span
    return text[max(0, s - pad): e + pad].strip()[:160]


def _apply(rule: Rule, text: str, via: str) -> Finding | None:
    m = rule.pattern.search(text)
    if not m:
        return None
    return Finding(rule.id, rule.category, rule.severity, rule.description,
                   _excerpt(text, m.span()), rule.owasp, via)


def scan(text: str, source: str = "user") -> ScanResult:
    """Scan untrusted text. `source` is one of user | retrieved | tool."""
    if source not in SOURCE_MULTIPLIER:
        raise ValueError(f"unknown source {source!r}")
    findings: dict[str, Finding] = {}

    normalized = normalize(text)
    for rule in RULES:
        f = _apply(rule, text, "plain")
        if f is None and normalized != text:
            f = _apply(rule, normalized, "normalized")
        if f:
            findings[rule.id] = f

    # Payloads hidden in base64 are re-scanned; the decode itself is a mild signal.
    for blob in decode_base64_blobs(text):
        hit = False
        for rule in RULES:
            f = _apply(rule, normalize(blob), "base64")
            if f and rule.id not in findings:
                findings[rule.id] = f
                hit = True
        if hit:
            findings["EV-BASE64"] = Finding(
                "EV-BASE64", "obfuscation", 3, "Instruction-like content hidden in base64.",
                blob[:80], "LLM01", "base64")

    hidden = count_invisible(text)
    if hidden >= 3:
        findings["EV-INVISIBLE"] = Finding(
            "EV-INVISIBLE", "obfuscation", 3,
            f"{hidden} invisible/bidi control characters (possible hidden text).",
            "", "LLM01", "plain")

    sevs = sorted((f.severity for f in findings.values()), reverse=True)
    # Strongest signal counts fully, additional signals diminish (avoids runaway sums).
    raw = sum(s * (0.5 ** i) for i, s in enumerate(sevs))
    score = round(raw * SOURCE_MULTIPLIER[source], 2)
    verdict = "block" if score >= BLOCK_AT or (sevs and sevs[0] >= 5 and source != "user") \
        else "review" if score >= REVIEW_AT else "allow"
    # A single sev-5 hit from a user is always at least review-worthy.
    if sevs and sevs[0] >= 5 and verdict == "allow":
        verdict = "review"
    ordered = sorted(findings.values(), key=lambda f: -f.severity)
    return ScanResult(score, verdict, source, ordered)
