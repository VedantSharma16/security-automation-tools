"""Orchestrates retrieval, indicator scoring, and narration into a single TriageResult."""

from typing import Optional

from .llm_backend import RuleBasedNarrator, TriageNarrator
from .models import Alert, TriageResult
from .retriever import TechniqueRetriever
from .scoring import classify_severity, recommended_actions_for, score_indicators


class TriageEngine:
    def __init__(
        self,
        retriever: TechniqueRetriever,
        narrator: Optional[TriageNarrator] = None,
        top_k: int = 3,
        technique_weight: float = 0.35,
        indicator_weight: float = 0.65,
    ):
        self.retriever = retriever
        self.narrator = narrator or RuleBasedNarrator()
        self.top_k = top_k
        self.technique_weight = technique_weight
        self.indicator_weight = indicator_weight

    def triage(self, alert: Alert) -> TriageResult:
        matches = self.retriever.retrieve(alert.text(), top_k=self.top_k)
        indicators, indicator_score = score_indicators(alert)

        top_score = matches[0].score if matches else 0.0
        risk_score = min(1.0, self.technique_weight * top_score + self.indicator_weight * indicator_score)
        severity = classify_severity(risk_score)

        top_tactic = matches[0].tactic if matches and matches[0].score > 0 else "default"
        actions = recommended_actions_for(top_tactic)
        rationale = self.narrator.summarize(alert, matches, indicators, severity)

        return TriageResult(
            alert_id=alert.id,
            severity=severity,
            risk_score=round(risk_score, 3),
            matched_techniques=matches,
            matched_indicators=indicators,
            recommended_actions=actions,
            rationale=rationale,
        )
