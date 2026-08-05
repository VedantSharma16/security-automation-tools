"""Shared finding/severity model used across all analysis modules."""

from __future__ import annotations

from dataclasses import dataclass

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class Finding:
    id: str
    severity: str
    category: str  # "header" | "cookie" | "tls" | "transport"
    message: str
    recommendation: str

    def __post_init__(self):
        if self.severity not in SEVERITY_RANK:
            raise ValueError(f"Unknown severity: {self.severity!r}")

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
            "recommendation": self.recommendation,
        }


def sort_by_severity(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: SEVERITY_RANK[f.severity], reverse=True)


def highest_severity(findings: list[Finding]) -> str | None:
    if not findings:
        return None
    return max((f.severity for f in findings), key=lambda s: SEVERITY_RANK[s])
