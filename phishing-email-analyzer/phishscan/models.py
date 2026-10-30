from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional

SEVERITY_POINTS = {"info": 0, "low": 10, "medium": 25, "high": 40}


@dataclass
class Finding:
    check: str
    severity: str  # info | low | medium | high
    description: str
    evidence: str = ""
    mitre: Optional[str] = None  # ATT&CK technique ID

    @property
    def points(self) -> int:
        return SEVERITY_POINTS[self.severity]


@dataclass
class Verdict:
    score: int
    label: str  # clean | suspicious | likely_phishing
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "label": self.label,
            "findings": [asdict(f) for f in self.findings],
        }
