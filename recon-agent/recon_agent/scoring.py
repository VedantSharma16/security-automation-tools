"""Risk scoring: turns a list of findings into a 0-100 score and A-F grade."""
from __future__ import annotations

from typing import List

from .models import Finding

SEVERITY_PENALTY = {
    "critical": 30,
    "high": 15,
    "medium": 7,
    "low": 3,
    "info": 0,
}


def score_findings(findings: List[Finding]) -> int:
    score = 100
    for finding in findings:
        score -= SEVERITY_PENALTY.get(finding.severity, 0)
    return max(score, 0)


def grade_for_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"
