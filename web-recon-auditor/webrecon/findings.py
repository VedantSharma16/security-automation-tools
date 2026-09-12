"""Shared finding type emitted by every scan module."""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_WEIGHTS = {"info": 0, "low": 10, "medium": 25, "high": 45, "critical": 70}
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


@dataclass
class Finding:
    id: str
    category: str  # "headers" | "paths" | "tls"
    severity: str  # one of SEVERITY_ORDER
    title: str
    detail: str
    recommendation: str
    evidence: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_WEIGHTS:
            raise ValueError(f"unknown severity: {self.severity!r}")

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
        }
