"""Input-side scanner: scores untrusted text (user prompts or retrieved RAG
chunks) for prompt-injection risk before it reaches the model.

Pipeline:
    raw text
      -> normalize()            strip zero-width / bidi / tag-smuggling, fold homoglyphs
      -> rule pack              on the normalized text + a leetspeak-folded view
      -> decoders               base64 / hex / rot13 segments are decoded and re-scanned
      -> score aggregation      noisy-OR over finding weights -> 0..100
      -> verdict                allow / review / block
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Iterable, Literal

from .classifier import DEFAULT_MODEL_PATH, NaiveBayes
from .decoders import find_encoded_segments
from .normalize import leet_fold, normalize
from .rules import Rule, load_rules

Source = Literal["user", "retrieved"]
Verdict = Literal["allow", "review", "block"]

# Retrieved content (web pages, emails, PDFs in a RAG index) has no business
# issuing instructions at all, so instruction-like content there is weighted
# up. This is the core asymmetry between direct and indirect injection.
INDIRECT_BOOST = 1.35
MAX_WEIGHT = 0.95
MAX_DECODE_DEPTH = 2

DEFAULT_REVIEW_THRESHOLD = 40
DEFAULT_BLOCK_THRESHOLD = 70

ML_BASE_WEIGHT = 0.45
ML_WEIGHT_SPAN = 0.3

EVASION_WEIGHTS = {
    "tag_smuggling": 0.7,
    "bidi": 0.4,
    "homoglyph": 0.4,
    "zero_width": 0.3,
    "encoded_payload": 0.45,
}


@dataclass
class Finding:
    rule_id: str
    name: str
    category: str
    weight: float
    evidence: str
    owasp: str = ""
    atlas: str = ""
    via: str = "plaintext"


@dataclass
class ScanResult:
    source: Source
    score: int
    verdict: Verdict
    findings: list[Finding] = field(default_factory=list)
    normalized_text: str = ""

    @property
    def categories(self) -> list[str]:
        return sorted({f.category for f in self.findings})

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "score": self.score,
            "verdict": self.verdict,
            "categories": self.categories,
            "findings": [asdict(f) for f in self.findings],
        }


def _snippet(text: str, start: int, end: int, pad: int = 25) -> str:
    lo, hi = max(0, start - pad), min(len(text), end + pad)
    return ("…" if lo else "") + text[lo:hi].replace("\n", " ") + ("…" if hi < len(text) else "")


def aggregate_score(weights: Iterable[float]) -> int:
    """Noisy-OR: independent signals compound with diminishing returns, so
    three weak hits outrank one weak hit but never exceed 100."""
    remaining = 1.0
    for w in weights:
        remaining *= 1.0 - w
    return round(100 * (1.0 - remaining))


class InjectionScanner:
    def __init__(
        self,
        rules: list[Rule] | None = None,
        review_threshold: int = DEFAULT_REVIEW_THRESHOLD,
        block_threshold: int = DEFAULT_BLOCK_THRESHOLD,
        classifier: NaiveBayes | None = None,
        use_classifier: bool = True,
    ):
        if not 0 < review_threshold < block_threshold <= 100:
            raise ValueError("thresholds must satisfy 0 < review < block <= 100")
        self.rules = rules if rules is not None else load_rules()
        self.review_threshold = review_threshold
        self.block_threshold = block_threshold
        if classifier is None and use_classifier and DEFAULT_MODEL_PATH.exists():
            classifier = NaiveBayes.load(DEFAULT_MODEL_PATH)
        self.classifier = classifier if use_classifier else None

    # -- rule matching -----------------------------------------------------

    def _match_rules(self, text: str, source: Source, via: str) -> list[Finding]:
        findings: list[Finding] = []
        views = [text]
        folded = leet_fold(text)
        if folded != text:
            views.append(folded)

        for rule in self.rules:
            for view in views:
                match = rule.pattern.search(view)
                if not match:
                    continue
                weight = rule.weight
                if source == "retrieved" and rule.indirect_boost:
                    weight = min(MAX_WEIGHT, weight * INDIRECT_BOOST)
                elif source == "retrieved":
                    weight = min(MAX_WEIGHT, weight * 1.15)
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        name=rule.name,
                        category=rule.category,
                        weight=round(weight, 3),
                        evidence=_snippet(view, match.start(), match.end()),
                        owasp=rule.owasp,
                        atlas=rule.atlas,
                        via=via if view is text else f"{via}+leetspeak",
                    )
                )
                break  # one hit per rule per layer is enough
        return findings

    def _scan_layer(self, text: str, source: Source, via: str, depth: int) -> list[Finding]:
        findings = self._match_rules(text, source, via)
        if depth >= MAX_DECODE_DEPTH:
            return findings
        for segment in find_encoded_segments(text):
            inner = self._scan_layer(segment.decoded, source, f"{via}>{segment.encoding}", depth + 1)
            if inner:
                findings.append(
                    Finding(
                        rule_id="EVA-ENC",
                        name=f"Instructions hidden in {segment.encoding}-encoded payload",
                        category="evasion",
                        weight=EVASION_WEIGHTS["encoded_payload"],
                        evidence=segment.decoded[:120],
                        owasp="LLM01:2025 Prompt Injection",
                        atlas="AML.T0051",
                        via=via,
                    )
                )
                findings.extend(inner)
        return findings

    # -- public API --------------------------------------------------------

    def scan(self, text: str, source: Source = "user") -> ScanResult:
        norm = normalize(text)
        findings: list[Finding] = []

        if norm.tag_smuggled_text:
            findings.append(Finding("EVA-TAG", "Unicode tag-block ASCII smuggling", "evasion",
                                    EVASION_WEIGHTS["tag_smuggling"], norm.tag_smuggled_text[:120],
                                    "LLM01:2025 Prompt Injection", "AML.T0051"))
        if norm.bidi_count:
            findings.append(Finding("EVA-BIDI", "Bidirectional override characters", "evasion",
                                    EVASION_WEIGHTS["bidi"], f"{norm.bidi_count} bidi control char(s)",
                                    "LLM01:2025 Prompt Injection", "AML.T0051"))
        if norm.homoglyph_tokens:
            findings.append(Finding("EVA-HOMO", "Mixed-script homoglyph obfuscation", "evasion",
                                    EVASION_WEIGHTS["homoglyph"], ", ".join(norm.homoglyph_tokens[:5]),
                                    "LLM01:2025 Prompt Injection", "AML.T0051"))
        # A lone BOM or soft hyphen is common in copy-pasted text; several
        # invisible characters is not.
        if norm.zero_width_count >= 3:
            findings.append(Finding("EVA-ZW", "Zero-width character keyword splitting", "evasion",
                                    EVASION_WEIGHTS["zero_width"], f"{norm.zero_width_count} invisible char(s)",
                                    "LLM01:2025 Prompt Injection", "AML.T0051"))

        findings.extend(self._scan_layer(norm.normalized, source, "plaintext", depth=0))

        if self.classifier is not None and self.classifier.is_malicious(norm.normalized):
            p = self.classifier.probability(norm.normalized)
            findings.append(Finding(
                rule_id="ML-NB",
                name="Statistical classifier: instruction-like content",
                category="ml_detection",
                weight=round(ML_BASE_WEIGHT + ML_WEIGHT_SPAN * (p - 0.5) / 0.5, 3),
                evidence=f"naive-bayes p(malicious)={p:.2f}",
                owasp="LLM01:2025 Prompt Injection",
                atlas="AML.T0051",
            ))

        # Evasion alone (e.g. a stray zero-width joiner in an emoji sequence)
        # is suspicious but not an attack; only let it drive a block when it
        # co-occurs with an actual instruction-pattern hit.
        has_semantic_hit = any(not f.rule_id.startswith("EVA-") for f in findings)
        weights = [f.weight if (has_semantic_hit or not f.rule_id.startswith("EVA-")) else f.weight * 0.6
                   for f in findings]
        score = aggregate_score(weights)

        # A classifier-only detection is not explainable enough to hard-block
        # on: route it to review (human or LLM judge) instead.
        rule_hit = any(not f.rule_id.startswith(("EVA-", "ML-")) for f in findings)
        if not rule_hit and score >= self.block_threshold:
            score = self.block_threshold - 1

        if score >= self.block_threshold:
            verdict: Verdict = "block"
        elif score >= self.review_threshold:
            verdict = "review"
        else:
            verdict = "allow"

        findings.sort(key=lambda f: f.weight, reverse=True)
        return ScanResult(source=source, score=score, verdict=verdict,
                          findings=findings, normalized_text=norm.normalized)


@dataclass
class ContextGuardResult:
    safe_chunks: list[str]
    quarantined: list[tuple[int, ScanResult]]


def guard_rag_context(
    chunks: list[str],
    scanner: InjectionScanner | None = None,
    quarantine_at: Verdict = "review",
) -> ContextGuardResult:
    """Filter retrieved chunks before they are stuffed into a prompt.

    Chunks at or above `quarantine_at` are withheld from the context window
    and returned separately (with their scan results) for logging/alerting.
    """
    scanner = scanner or InjectionScanner()
    rank = {"allow": 0, "review": 1, "block": 2}
    safe, quarantined = [], []
    for i, chunk in enumerate(chunks):
        result = scanner.scan(chunk, source="retrieved")
        if rank[result.verdict] >= rank[quarantine_at]:
            quarantined.append((i, result))
        else:
            safe.append(chunk)
    return ContextGuardResult(safe_chunks=safe, quarantined=quarantined)
