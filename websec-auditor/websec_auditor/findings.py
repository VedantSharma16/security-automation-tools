"""Shared finding model used by every analyzer in websec_auditor."""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")

# Points subtracted from the base score of 100 for each finding of this
# severity. "info" findings (e.g. fingerprinted technology) never cost
# points -- they're observations, not misconfigurations.
SEVERITY_WEIGHT = {
    "info": 0,
    "low": 3,
    "medium": 8,
    "high": 15,
    "critical": 25,
}


@dataclass(frozen=True)
class Finding:
    id: str
    severity: str
    category: str
    message: str
    recommendation: str = ""
    evidence: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_WEIGHT:
            raise ValueError(
                f"Unknown severity {self.severity!r}; must be one of {SEVERITY_ORDER}"
            )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
        }
