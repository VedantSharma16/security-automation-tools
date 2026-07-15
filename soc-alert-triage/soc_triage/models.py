"""Core data structures shared across the triage pipeline."""

from dataclasses import dataclass, field
from typing import List


@dataclass
class Alert:
    """A single security event to be triaged, e.g. from an EDR or auth log."""

    id: str
    timestamp: str
    source: str
    host: str
    user: str
    process_name: str
    command_line: str
    description: str = ""

    def text(self) -> str:
        """Flatten the alert into a single string for retrieval/scoring."""
        return f"{self.process_name} {self.command_line} {self.description}"


@dataclass
class TechniqueMatch:
    """A MITRE ATT&CK technique retrieved as relevant to an alert, with a similarity score."""

    technique_id: str
    name: str
    tactic: str
    score: float


@dataclass
class TriageResult:
    """The output of triaging one alert: severity, evidence, and next steps."""

    alert_id: str
    severity: str
    risk_score: float
    matched_techniques: List[TechniqueMatch]
    matched_indicators: List[str]
    recommended_actions: List[str]
    rationale: str
