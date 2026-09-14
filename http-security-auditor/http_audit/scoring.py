"""Weighted scoring: findings -> 0-100 score -> letter grade."""

from __future__ import annotations

from http_audit.report import Finding

_PENALTY_BY_SEVERITY: dict[str, int] = {
    "critical": 35,
    "high": 20,
    "medium": 10,
    "low": 5,
    "info": 0,
    "pass": 0,
}

_GRADE_THRESHOLDS: list[tuple[int, str]] = [
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
]


def score_findings(findings: list[Finding]) -> int:
    score = 100
    for finding in findings:
        score -= _PENALTY_BY_SEVERITY.get(finding.severity, 0)
    return max(0, min(100, score))


def grade_for_score(score: int) -> str:
    for threshold, grade in _GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"
