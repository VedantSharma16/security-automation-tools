"""Core scanner: normalizes input, runs rules over every view, scores risk, returns a verdict."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from injection_guard import normalize
from injection_guard.rules import RULES

# Content that no user typed is more dangerous when it carries instructions.
SOURCE_MULTIPLIER = {"user": 1.0, "retrieved_doc": 1.3, "tool_output": 1.3, "web": 1.4}
BLOCK_THRESHOLD = 70
FLAG_THRESHOLD = 35
_VIEW_DISCOUNT = {"original": 1.0, "folded": 1.0, "base64": 1.0, "rot13": 0.6}


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: int
    view: str
    evidence: str
    description: str
    reference: str


@dataclass
class ScanResult:
    verdict: str  # allow | flag | block
    score: int
    source: str
    findings: list[Finding] = field(default_factory=list)
    obfuscation: list[str] = field(default_factory=list)

    @property
    def categories(self) -> list[str]:
        return sorted({f.category for f in self.findings})

    def to_dict(self) -> dict:
        d = asdict(self)
        d["categories"] = self.categories
        return d


def _views(text: str) -> list[tuple[str, str]]:
    views = [("original", text)]
    folded = normalize.fold(text)
    if folded != text.lower():
        views.append(("folded", folded))
    views.extend(normalize.decode_payloads(text))
    return views


def scan(text: str, source: str = "user") -> ScanResult:
    """Scan ``text`` for prompt-injection indicators.

    ``source`` is one of user | retrieved_doc | tool_output | web; untrusted
    sources raise the score because instructions there are never legitimate.
    """
    if source not in SOURCE_MULTIPLIER:
        raise ValueError(f"unknown source {source!r}; expected one of {sorted(SOURCE_MULTIPLIER)}")

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for view, body in _views(text):
        for rule in RULES:
            m = rule.pattern.search(body)
            if not m or (rule.id, m.group(0).lower()) in seen:
                continue
            # a hit in a normalized view that also hit in 'original' is a duplicate
            if any(f.rule_id == rule.id for f in findings):
                continue
            seen.add((rule.id, m.group(0).lower()))
            findings.append(Finding(rule.id, rule.category, rule.severity, view,
                                    m.group(0)[:120], rule.description, rule.reference))

    obfuscation: list[str] = []
    if normalize.count_invisible(text) >= 3:
        obfuscation.append("invisible_characters")
    if normalize.has_confusables(text):
        obfuscation.append("homoglyphs")
    if any(f.view in ("base64", "rot13") for f in findings):
        obfuscation.append("encoded_payload")

    score = _score(findings, obfuscation, source)
    verdict = "block" if score >= BLOCK_THRESHOLD else "flag" if score >= FLAG_THRESHOLD else "allow"
    return ScanResult(verdict, score, source, findings, obfuscation)


def _score(findings: list[Finding], obfuscation: list[str], source: str) -> int:
    if not findings:
        # obfuscation alone is suspicious but not conclusive
        return min(20, 10 * len(obfuscation))
    ranked = sorted((f.severity * 10 * _VIEW_DISCOUNT[f.view] for f in findings), reverse=True)
    # top finding dominates; each extra independent finding adds diminishing weight
    base = ranked[0] + sum(r * 0.3 for r in ranked[1:])
    base += 10 * len(obfuscation)
    base *= SOURCE_MULTIPLIER[source]
    return min(100, round(base))
