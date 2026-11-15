"""The firewall facade: fuse normalisation, signatures, ML and an optional
LLM judge into one allow / flag / block decision.

Scoring
-------
* ``rule_score``  = 1 - prod(1 - w_i) over matched rules and obfuscation
  signals (noisy-OR: independent pieces of evidence reinforce each other).
* ``ml_score``    = Naive Bayes P(malicious).
* ``fused``       = max(rule_score, ML_WEIGHT * ml_score + (1 - ML_WEIGHT) * rule_score)

so a strong signature alone can block, while the ML model can only push a
paraphrase into ``flag`` territory on its own - a deliberate bias toward
precision for user-facing traffic.

Retrieved content (RAG chunks, web pages, emails, tool output) is scanned
with lower thresholds: legitimate documents almost never address the AI
reading them, so the false-positive cost of being strict is low and the
cost of an indirect injection reaching an agent with tools is high.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal

from .classifier import NaiveBayes, train_default
from .judge import LLMJudge
from .normalize import normalize
from .output_guard import OutputFinding, redact, scan_output
from .rules import RuleHit, match_rules

Source = Literal["user", "retrieved"]
Action = Literal["allow", "flag", "block"]

ML_WEIGHT = 0.55

OBFUSCATION_WEIGHTS = {
    "unicode_tags": 0.6,  # invisible instructions: essentially never benign
    "invisible_chars": 0.15,
    "homoglyphs": 0.2,
    "letter_spacing": 0.05,
    "encoded_payload": 0.05,
    "fullwidth": 0.05,
}

THRESHOLDS: dict[str, tuple[float, float]] = {
    # source: (flag_at, block_at)
    "user": (0.45, 0.75),
    "retrieved": (0.35, 0.6),
}


@dataclass
class Verdict:
    action: Action
    score: float
    rule_score: float
    ml_score: float
    source: str
    hits: list[RuleHit] = field(default_factory=list)
    obfuscation: list[str] = field(default_factory=list)
    ml_features: list[tuple[str, float]] = field(default_factory=list)
    judge: dict | None = None

    @property
    def categories(self) -> list[str]:
        return sorted({h.category for h in self.hits})

    @property
    def atlas_techniques(self) -> list[str]:
        return sorted({h.atlas for h in self.hits})

    def to_dict(self) -> dict:
        data = asdict(self)
        data["categories"] = self.categories
        data["atlas_techniques"] = self.atlas_techniques
        data["score"] = round(self.score, 3)
        data["rule_score"] = round(self.rule_score, 3)
        data["ml_score"] = round(self.ml_score, 3)
        data["ml_features"] = [(t, round(w, 2)) for t, w in self.ml_features]
        return data


@dataclass
class OutputVerdict:
    action: Action
    findings: list[OutputFinding]
    redacted_text: str

    def to_dict(self) -> dict:
        return {"action": self.action, "findings": [asdict(f) for f in self.findings], "redacted_text": self.redacted_text}


def _noisy_or(weights: list[float]) -> float:
    remaining = 1.0
    for w in weights:
        remaining *= 1.0 - w
    return 1.0 - remaining


class Firewall:
    def __init__(
        self,
        model: NaiveBayes | None = None,
        judge: LLMJudge | None = None,
        *,
        use_rules: bool = True,
        use_ml: bool = True,
        thresholds: dict[str, tuple[float, float]] | None = None,
    ):
        self.model = model if model is not None else (train_default() if use_ml else None)
        self.judge = judge
        self.use_rules = use_rules
        self.use_ml = use_ml
        self.thresholds = thresholds or THRESHOLDS

    # ------------------------------------------------------------------ input
    def scan_input(self, text: str, source: Source = "user") -> Verdict:
        if source not in self.thresholds:
            raise ValueError(f"unknown source {source!r}; expected one of {sorted(self.thresholds)}")
        normalized = normalize(text)

        hits = match_rules(normalized) if self.use_rules else []
        obfuscation = [s.kind for s in normalized.signals]
        rule_weights = [h.weight for h in hits]
        if self.use_rules:
            rule_weights += [OBFUSCATION_WEIGHTS.get(k, 0.0) for k in obfuscation]
        rule_score = _noisy_or(rule_weights)

        ml_score, features = 0.0, []
        if self.use_ml and self.model is not None:
            # Score the de-obfuscated view plus any decoded payloads.
            ml_text = " ".join(t for _, t in normalized.views())
            ml_score = self.model.predict_proba(ml_text)
            features = self.model.top_features(ml_text, k=5) if ml_score >= 0.5 else []

        if self.use_rules and self.use_ml:
            score = max(rule_score, ML_WEIGHT * ml_score + (1 - ML_WEIGHT) * rule_score)
        else:
            score = rule_score if self.use_rules else ml_score

        flag_at, block_at = self.thresholds[source]
        action: Action = "block" if score >= block_at else "flag" if score >= flag_at else "allow"

        verdict = Verdict(action, score, rule_score, ml_score, source, hits, obfuscation, features)

        if action == "flag" and self.judge is not None and self.judge.available:
            opinion = self.judge.classify(text)
            if opinion is not None:
                verdict.judge = asdict(opinion)
                if opinion.is_attack and opinion.confidence >= 0.7:
                    verdict.action = "block"
                elif not opinion.is_attack and opinion.confidence >= 0.8 and not hits:
                    # Only an ML-only flag can be cleared; signature hits stand.
                    verdict.action = "allow"
        return verdict

    def scan_retrieved(self, documents: list[str]) -> tuple[list[str], list[Verdict]]:
        """Screen RAG chunks / tool output before they enter the context window.

        Returns (documents safe to include, verdict per input document).
        Flagged documents are kept but should be fenced as untrusted data;
        blocked documents are dropped.
        """
        verdicts = [self.scan_input(doc, source="retrieved") for doc in documents]
        safe = [doc for doc, v in zip(documents, verdicts) if v.action != "block"]
        return safe, verdicts

    # ----------------------------------------------------------------- output
    def scan_output(
        self,
        text: str,
        *,
        canary: str | None = None,
        system_prompt: str | None = None,
        allowed_domains: set[str] | frozenset[str] = frozenset(),
    ) -> OutputVerdict:
        findings = scan_output(text, canary=canary, system_prompt=system_prompt, allowed_domains=allowed_domains)
        severities = {f.severity for f in findings}
        action: Action = "block" if {"critical", "high"} & severities else "flag" if findings else "allow"
        return OutputVerdict(action, findings, redact(text, findings))
