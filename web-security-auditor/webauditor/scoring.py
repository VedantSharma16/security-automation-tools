"""Aggregate a list of findings into a numeric score and letter grade."""

from __future__ import annotations

from typing import List

from .models import Finding, Severity, Status

FAIL_WEIGHTS = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 18,
    Severity.MEDIUM: 9,
    Severity.LOW: 3,
    Severity.INFO: 0,
}
WARN_MULTIPLIER = 0.5

GRADE_THRESHOLDS = (
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
)


def compute_score(findings: List[Finding]) -> int:
    """Return a 0-100 score, deducting points for each fail/warn finding."""
    score = 100.0
    for finding in findings:
        weight = FAIL_WEIGHTS.get(finding.severity, 0)
        if finding.status == Status.FAIL:
            score -= weight
        elif finding.status == Status.WARN:
            score -= weight * WARN_MULTIPLIER
    return max(0, round(score))


def grade_for_score(score: int) -> str:
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"
