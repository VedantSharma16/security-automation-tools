"""Turn a list of findings into a 0-100 score and an A-F letter grade."""

from __future__ import annotations

from .models import Finding

SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 25,
    "high": 15,
    "medium": 7,
    "low": 3,
    "info": 0,
}

_GRADE_THRESHOLDS: tuple[tuple[int, str], ...] = (
    (90, "A"),
    (75, "B"),
    (60, "C"),
    (40, "D"),
)


def compute_score(findings: list[Finding]) -> int:
    deductions = sum(SEVERITY_WEIGHTS[f.severity] for f in findings)
    return max(0, 100 - deductions)


def grade_for_score(score: int) -> str:
    for threshold, grade in _GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"
