"""Orchestrates extraction, enrichment, RAG retrieval, and summarization."""

from __future__ import annotations

from dataclasses import dataclass

from ioc_triage.enrichment import EnrichmentResult, enrich_indicators, load_threat_intel
from ioc_triage.extractor import Indicator, extract_iocs
from ioc_triage.knowledge_base import Technique, TechniqueKnowledgeBase
from ioc_triage.llm_client import LLMClient, TriageContext

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

_HIGH_IMPACT_TACTICS = {"Impact", "Exfiltration", "Credential Access"}
_HIGH_IMPACT_RELEVANCE_THRESHOLD = 0.15
_GENERAL_RELEVANCE_THRESHOLD = 0.3


@dataclass
class TriageReport:
    alert_text: str
    indicators: list[Indicator]
    enrichment: list[EnrichmentResult]
    matched_techniques: list[tuple[Technique, float]]
    severity: str
    summary: str
    llm_backed: bool

    def to_dict(self) -> dict:
        return {
            "alert_text": self.alert_text,
            "indicators": [i.to_dict() for i in self.indicators],
            "enrichment": [e.to_dict() for e in self.enrichment],
            "matched_techniques": [
                {**technique.to_dict(), "relevance": round(score, 3)}
                for technique, score in self.matched_techniques
            ],
            "severity": self.severity,
            "summary": self.summary,
            "llm_backed": self.llm_backed,
        }


def score_severity(
    enrichment: list[EnrichmentResult], matched_techniques: list[tuple[Technique, float]]
) -> str:
    """Heuristic severity scoring from enrichment hits and matched tactics."""
    high_confidence_hits = [
        e for e in enrichment if e.is_known_malicious and e.confidence == "high"
    ]
    any_hits = [e for e in enrichment if e.is_known_malicious]
    high_impact_match = any(
        tactic.strip() in _HIGH_IMPACT_TACTICS
        for technique, score in matched_techniques
        for tactic in technique.tactic.split(",")
        if score >= _HIGH_IMPACT_RELEVANCE_THRESHOLD
    )
    # Retrieval alone (without a threat-intel hit) is context for the analyst,
    # not proof of malice — only count it toward severity above a stricter bar.
    strong_technique_match = any(score >= _GENERAL_RELEVANCE_THRESHOLD for _, score in matched_techniques)

    if high_confidence_hits and high_impact_match:
        return SEVERITY_CRITICAL
    if high_confidence_hits or (any_hits and high_impact_match):
        return SEVERITY_HIGH
    if any_hits or strong_technique_match:
        return SEVERITY_MEDIUM
    return SEVERITY_LOW


def run_triage(
    alert_text: str,
    knowledge_base: TechniqueKnowledgeBase | None = None,
    threat_intel: dict | None = None,
    llm_client: LLMClient | None = None,
    top_k_techniques: int = 3,
) -> TriageReport:
    """Run the full extract -> enrich -> retrieve -> summarize pipeline."""
    knowledge_base = knowledge_base or TechniqueKnowledgeBase.from_file()
    threat_intel = threat_intel if threat_intel is not None else load_threat_intel()
    llm_client = llm_client or LLMClient()

    indicators = extract_iocs(alert_text)
    enrichment = enrich_indicators(indicators, threat_intel)
    matched_techniques = knowledge_base.query(alert_text, top_k=top_k_techniques)
    severity = score_severity(enrichment, matched_techniques)

    context = TriageContext(
        alert_text=alert_text,
        indicators=[i.to_dict() for i in indicators],
        enrichment=[e.to_dict() for e in enrichment],
        matched_techniques=[(t.to_dict(), s) for t, s in matched_techniques],
        severity=severity,
    )
    summary = llm_client.summarize(context)

    return TriageReport(
        alert_text=alert_text,
        indicators=indicators,
        enrichment=enrichment,
        matched_techniques=matched_techniques,
        severity=severity,
        summary=summary,
        llm_backed=llm_client.is_live,
    )
