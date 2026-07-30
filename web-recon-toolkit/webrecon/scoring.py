"""Aggregate a list of findings into a severity breakdown and a 0-100 risk score."""

from __future__ import annotations

from .models import Finding, Severity

_RISK_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 15,
    Severity.HIGH: 30,
    Severity.CRITICAL: 50,
}


def build_summary(findings: list[Finding]) -> dict:
    by_severity = {s.name: 0 for s in Severity}
    for f in findings:
        by_severity[f.severity.name] += 1

    risk_score = min(100, sum(_RISK_WEIGHT[f.severity] for f in findings))
    highest = max((f.severity for f in findings), default=None)

    return {
        "total_findings": len(findings),
        "by_severity": by_severity,
        "risk_score": risk_score,
        "highest_severity": highest.name if highest else None,
    }
