"""Input-side scanner: normalize -> run rules over every text view -> score.

The scanner is deterministic, dependency-free and fast enough to sit inline
in front of every LLM call (and every retrieved RAG chunk). Its output is a
structured `ScanResult` that an application can act on directly
(allow / review / block) or hand to the optional LLM judge for a second
opinion on borderline cases.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .normalize import normalize
from .rules import rules_for_source

DEFAULT_REVIEW_THRESHOLD = 0.4
DEFAULT_BLOCK_THRESHOLD = 0.7

# Weight of obfuscation signals that are suspicious on their own.
OBFUSCATION_WEIGHTS = {
    "unicode-tag-smuggling": 0.6,   # invisible ASCII-mirroring text: almost never benign
    "bidi-or-many-invisible": 0.3,
}
# Extra weight when a rule only fires *after* de-obfuscation — someone hid it.
EVASION_WEIGHT = 0.25


@dataclass
class Finding:
    rule_id: str
    category: str
    description: str
    weight: float
    owasp: str
    atlas: str
    matched: str
    view: str  # "normalized" | "deobfuscated" | "decoded-payload"


@dataclass
class ScanResult:
    source: str
    risk_score: float
    verdict: str  # "allow" | "review" | "block"
    findings: list[Finding] = field(default_factory=list)
    obfuscation: list[str] = field(default_factory=list)
    evasion_detected: bool = False

    @property
    def categories(self) -> list[str]:
        return sorted({f.category for f in self.findings})

    def to_dict(self) -> dict:
        d = asdict(self)
        d["categories"] = self.categories
        return d


def _noisy_or(weights: list[float]) -> float:
    """Combine independent signal weights: 1 - prod(1 - w)."""
    p = 1.0
    for w in weights:
        p *= 1.0 - max(0.0, min(1.0, w))
    return 1.0 - p


def _verdict(score: float, review: float, block: float) -> str:
    if score >= block:
        return "block"
    if score >= review:
        return "review"
    return "allow"


def _snippet(text: str, start: int, end: int, pad: int = 20) -> str:
    s = max(0, start - pad)
    e = min(len(text), end + pad)
    return ("…" if s else "") + text[s:e] + ("…" if e < len(text) else "")


def scan_input(
    text: str,
    source: str = "user",
    review_threshold: float = DEFAULT_REVIEW_THRESHOLD,
    block_threshold: float = DEFAULT_BLOCK_THRESHOLD,
) -> ScanResult:
    """Scan a piece of text that is about to enter an LLM context window.

    `source` is where the text came from: "user" (chat input), "retrieved"
    (RAG chunk, web page, email, document) or "tool" (tool/function output).
    Indirect-injection rules only apply to retrieved/tool content.
    """
    nt = normalize(text)
    views = [("normalized", nt.normalized), ("deobfuscated", nt.deobfuscated)]
    views += [("decoded-payload", p) for p in nt.decoded_payloads]

    findings: list[Finding] = []
    for rule in rules_for_source(source):
        for view_name, view_text in views:
            m = rule.pattern.search(view_text)
            if m:
                findings.append(Finding(
                    rule_id=rule.id, category=rule.category, description=rule.description,
                    weight=rule.weight, owasp=rule.owasp, atlas=rule.atlas,
                    matched=_snippet(view_text, m.start(), m.end()), view=view_name,
                ))
                break  # first (least-transformed) view that matches wins

    weights = [f.weight for f in findings]
    evasion = any(f.view != "normalized" for f in findings)
    if evasion:
        weights.append(EVASION_WEIGHT)

    obf = list(nt.obfuscation)
    if "unicode-tag-smuggling" in obf:
        weights.append(OBFUSCATION_WEIGHTS["unicode-tag-smuggling"])
    invisible = next((int(o.split(":")[1]) for o in obf if o.startswith("invisible-characters:")), 0)
    if invisible >= 3 and "unicode-tag-smuggling" not in obf:
        weights.append(OBFUSCATION_WEIGHTS["bidi-or-many-invisible"])

    score = round(_noisy_or(weights), 3)
    return ScanResult(
        source=source,
        risk_score=score,
        verdict=_verdict(score, review_threshold, block_threshold),
        findings=findings,
        obfuscation=obf,
        evasion_detected=evasion,
    )
