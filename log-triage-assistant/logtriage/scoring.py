"""Severity model and aggregate risk scoring for detector findings."""

from __future__ import annotations

from enum import IntEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .detectors import Finding


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


_RISK_WEIGHT = {
    Severity.LOW: 5,
    Severity.MEDIUM: 15,
    Severity.HIGH: 30,
    Severity.CRITICAL: 50,
}


def build_summary(findings: list[Finding]) -> dict:
    """Aggregate a list of findings into a severity breakdown and a 0-100 risk score."""
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
