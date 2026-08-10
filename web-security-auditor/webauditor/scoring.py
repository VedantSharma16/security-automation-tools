"""Aggregate findings from all checkers into a single risk summary."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .findings import Severity

if TYPE_CHECKING:
    from .findings import Finding

_RISK_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 4,
    Severity.MEDIUM: 12,
    Severity.HIGH: 25,
    Severity.CRITICAL: 40,
}

def _rating_for(score: int, highest: Severity | None) -> str:
    """A single severe finding dominates the rating, regardless of overall score."""
    if highest == Severity.CRITICAL:
        return "CRITICAL"
    if highest == Severity.HIGH or score >= 40:
        return "POOR"
    if score >= 15:
        return "FAIR"
    return "GOOD"


def build_summary(findings: list[Finding]) -> dict:
    """Aggregate findings into a severity breakdown, 0-100 risk score, and rating."""
    by_severity = {s.name: 0 for s in Severity}
    for f in findings:
        by_severity[f.severity.name] += 1

    risk_score = min(100, sum(_RISK_WEIGHT[f.severity] for f in findings))
    highest = max((f.severity for f in findings), default=None)

    return {
        "total_findings": len(findings),
        "by_severity": by_severity,
        "risk_score": risk_score,
        "risk_rating": _rating_for(risk_score, highest),
        "highest_severity": highest.name if highest else None,
    }
