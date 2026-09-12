"""Aggregate findings into a severity breakdown and a 0-100 risk score."""

from __future__ import annotations

from dataclasses import dataclass

from .findings import SEVERITY_ORDER, SEVERITY_WEIGHTS, Finding

# Diminishing returns on repeated findings of the same severity: the first
# "high" matters a lot, the fifth "high" is the same underlying posture
# problem showing up again, not five times the risk.
_REPEAT_DECAY = 0.6


@dataclass
class RiskAssessment:
    score: int
    overall_severity: str
    severity_counts: dict[str, int]


def assess_risk(findings: list[Finding]) -> RiskAssessment:
    severity_counts = {sev: 0 for sev in SEVERITY_ORDER}
    for finding in findings:
        severity_counts[finding.severity] += 1

    total = 0.0
    for sev in SEVERITY_ORDER:
        weight = SEVERITY_WEIGHTS[sev]
        count = severity_counts[sev]
        for i in range(count):
            total += weight * (_REPEAT_DECAY**i)

    score = min(100, round(total))

    overall = "info"
    for sev in SEVERITY_ORDER:
        if severity_counts[sev] > 0:
            overall = sev
    if score >= 70:
        overall = "critical"
    elif score >= 45 and SEVERITY_ORDER.index(overall) < SEVERITY_ORDER.index("high"):
        overall = "high"

    return RiskAssessment(score=score, overall_severity=overall, severity_counts=severity_counts)
