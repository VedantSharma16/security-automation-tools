"""Turns a list of findings into a 0-100 score and a securityheaders.com-style letter grade."""

from __future__ import annotations

from .findings import Finding

SEVERITY_PENALTY = {
    "critical": 30,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}

_GRADE_THRESHOLDS = (
    (95, "A+"),
    (85, "A"),
    (70, "B"),
    (55, "C"),
    (40, "D"),
)
GRADE_ORDER = ["F", "D", "C", "B", "A", "A+"]


def compute_score(findings: list[Finding]) -> int:
    score = 100
    for f in findings:
        score -= SEVERITY_PENALTY.get(f.severity, 0)
    return max(0, min(100, score))


def grade_for_score(score: int) -> str:
    for threshold, grade in _GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def meets_minimum_grade(grade: str, minimum: str) -> bool:
    return GRADE_ORDER.index(grade) >= GRADE_ORDER.index(minimum)
