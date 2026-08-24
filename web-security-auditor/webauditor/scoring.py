"""Aggregate findings into a severity breakdown and a 0-100 risk score."""

from __future__ import annotations

from .findings import Finding, Severity

_RISK_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 15,
    Severity.HIGH: 30,
    Severity.CRITICAL: 50,
}

# (minimum risk_score, rating label), checked highest-first
_RATING_THRESHOLDS = (
    (70, "critical"),
    (40, "high"),
    (15, "medium"),
    (1, "low"),
)


def build_summary(findings: list[Finding]) -> dict:
    by_severity = {s.name: 0 for s in Severity}
    for f in findings:
        by_severity[f.severity.name] += 1

    risk_score = min(100, sum(_RISK_WEIGHT[f.severity] for f in findings))
    highest = max((f.severity for f in findings), default=None)

    rating = "none"
    for threshold, label in _RATING_THRESHOLDS:
        if risk_score >= threshold:
            rating = label
            break

    return {
        "total_findings": len(findings),
        "by_severity": by_severity,
        "risk_score": risk_score,
        "highest_severity": highest.name if highest else None,
        "risk_rating": rating,
    }
