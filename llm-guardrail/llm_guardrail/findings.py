"""Shared data types: findings, actions, verdicts, and risk aggregation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum

# OWASP Top 10 for LLM Applications (2025) identifiers used to tag findings.
OWASP = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
}


class Action(str, Enum):
    ALLOW = "allow"
    FLAG = "flag"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"

    @property
    def rank(self) -> int:
        return _ACTION_RANK[self]


_ACTION_RANK = {Action.ALLOW: 0, Action.FLAG: 1, Action.REQUIRE_APPROVAL: 2, Action.BLOCK: 3}


def strongest(*actions: Action) -> Action:
    return max(actions, key=lambda a: a.rank) if actions else Action.ALLOW


def severity_for(weight: float) -> str:
    if weight >= 0.9:
        return "critical"
    if weight >= 0.7:
        return "high"
    if weight >= 0.45:
        return "medium"
    return "low"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    weight: float
    owasp: str
    description: str
    evidence: str = ""

    @property
    def severity(self) -> str:
        return severity_for(self.weight)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity
        data["owasp_name"] = OWASP.get(self.owasp, "")
        return data


def combine_risk(findings: list[Finding]) -> float:
    """Noisy-OR aggregation: independent weak signals add up, but the score
    never exceeds 1.0 and one strong signal dominates."""
    remaining = 1.0
    for finding in findings:
        remaining *= 1.0 - max(0.0, min(1.0, finding.weight))
    return round(1.0 - remaining, 4)


@dataclass
class Verdict:
    context: str
    action: Action
    risk_score: float
    findings: list[Finding] = field(default_factory=list)
    redacted_text: str | None = None
    judge: dict | None = None

    @property
    def blocked(self) -> bool:
        return self.action is Action.BLOCK

    def to_dict(self) -> dict:
        data = {
            "context": self.context,
            "action": self.action.value,
            "risk_score": self.risk_score,
            "findings": [f.to_dict() for f in self.findings],
        }
        if self.redacted_text is not None:
            data["redacted_text"] = self.redacted_text
        if self.judge is not None:
            data["judge"] = self.judge
        return data


def snippet(text: str, start: int, end: int, pad: int = 20) -> str:
    lo, hi = max(0, start - pad), min(len(text), end + pad)
    out = text[lo:hi].replace("\n", " ")
    return ("…" if lo else "") + out + ("…" if hi < len(text) else "")
