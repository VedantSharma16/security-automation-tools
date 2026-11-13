"""Rule + signal based prompt-injection detector.

Each rule and obfuscation signal carries a weight in ``(0, 1)`` that can be
read as "how likely is this evidence, on its own, to indicate an injection".
Evidence is combined with a *noisy-OR*::

    p = 1 - prod(1 - w_i)

so independent pieces of weak evidence accumulate, no single weak rule can
block on its own, and adding evidence never lowers the score.

Text is scored relative to its **source**:

* ``user`` - the person talking to the app. Users legitimately give
  instructions, so thresholds are higher.
* ``retrieved`` - RAG chunks, web pages, emails, tool output. This is a data
  channel: it should *never* contain instructions to the model, so thresholds
  are lower and source-specific rules (e.g. text addressed to "the AI") apply.

All findings map to OWASP Top 10 for LLM Applications **LLM01: Prompt
Injection**.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from importlib import resources
from typing import Iterable

from .normalize import normalize

SOURCES = ("user", "retrieved")

SIGNAL_WEIGHTS = {
    "unicode_tag_smuggling": 0.8,  # invisible text has no legitimate use in a prompt
    "bidi_control_chars": 0.35,
    "homoglyph_mixing": 0.35,
    "zero_width_chars": 0.2,
    "fullwidth_forms": 0.15,
    "base64_payload": 0.1,
    # Added by the detector when a decoded base64 blob itself matches a rule.
    "encoded_instructions": 0.5,
}

THRESHOLDS = {
    # source: (flag_at, block_at) on a 0-100 scale
    "user": (40, 70),
    "retrieved": (30, 55),
}

OWASP_ID = "LLM01:2025 Prompt Injection"


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    category: str
    weight: float
    pattern: re.Pattern
    description: str
    sources: tuple[str, ...] = SOURCES


@dataclass
class RuleMatch:
    rule_id: str
    name: str
    category: str
    weight: float
    excerpt: str


@dataclass
class ScanResult:
    source: str
    score: int
    verdict: str  # "allow" | "flag" | "block"
    matches: list[RuleMatch] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)
    owasp: str = OWASP_ID

    @property
    def is_injection(self) -> bool:
        return self.verdict != "allow"

    @property
    def categories(self) -> list[str]:
        return sorted({m.category for m in self.matches})

    def to_dict(self) -> dict:
        d = asdict(self)
        d["categories"] = self.categories
        return d


def load_rules(path: str | None = None) -> list[Rule]:
    if path:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
    else:
        raw = json.loads(resources.files("injection_guard").joinpath("data/rules.json").read_text("utf-8"))
    rules = []
    for r in raw["rules"]:
        if not 0 < r["weight"] < 1:
            raise ValueError(f"rule {r['id']}: weight must be in (0, 1)")
        rules.append(
            Rule(
                id=r["id"],
                name=r["name"],
                category=r["category"],
                weight=r["weight"],
                pattern=re.compile(r["pattern"], re.IGNORECASE | re.MULTILINE),
                description=r["description"],
                sources=tuple(r.get("sources", SOURCES)),
            )
        )
    return rules


def _noisy_or(weights: Iterable[float]) -> float:
    p_clean = 1.0
    for w in weights:
        p_clean *= 1.0 - w
    return 1.0 - p_clean


def _excerpt(text: str, m: re.Match, width: int = 30) -> str:
    start, end = max(0, m.start() - width), min(len(text), m.end() + width)
    snippet = text[start:end].replace("\n", " ")
    return ("..." if start else "") + snippet + ("..." if end < len(text) else "")


class Detector:
    def __init__(self, rules: list[Rule] | None = None, thresholds: dict | None = None):
        self.rules = rules if rules is not None else load_rules()
        self.thresholds = thresholds or THRESHOLDS

    def _match_rules(self, text: str, source: str) -> list[RuleMatch]:
        found = []
        for rule in self.rules:
            if source not in rule.sources:
                continue
            m = rule.pattern.search(text)
            if m:
                found.append(RuleMatch(rule.id, rule.name, rule.category, rule.weight, _excerpt(text, m)))
        return found

    def scan(self, text: str, source: str = "user") -> ScanResult:
        if source not in SOURCES:
            raise ValueError(f"source must be one of {SOURCES}, got {source!r}")

        norm = normalize(text)
        signals = list(norm.signals)
        matches = self._match_rules(norm.text, source)

        # Scan decoded base64 separately so we can tell "encoded *and* malicious"
        # apart from harmless base64 (e.g. an embedded image or token).
        seen = {m.rule_id for m in matches}
        for segment in norm.decoded_segments:
            hidden = self._match_rules(segment, source)
            if hidden and "encoded_instructions" not in signals:
                signals.append("encoded_instructions")
            for h in hidden:
                if h.rule_id not in seen:
                    matches.append(h)
                    seen.add(h.rule_id)

        weights = [m.weight for m in matches] + [SIGNAL_WEIGHTS.get(s, 0.1) for s in signals]
        score = round(100 * _noisy_or(weights))
        flag_at, block_at = self.thresholds[source]
        verdict = "block" if score >= block_at else "flag" if score >= flag_at else "allow"
        return ScanResult(source=source, score=score, verdict=verdict, matches=matches, signals=signals)


_default: Detector | None = None


def scan(text: str, source: str = "user") -> ScanResult:
    """Convenience wrapper around a lazily-created default :class:`Detector`."""
    global _default
    if _default is None:
        _default = Detector()
    return _default.scan(text, source)
