"""Turn a list of findings into a Mozilla-Observatory-style score and letter grade."""

from __future__ import annotations

from .findings import Finding, SEVERITY_WEIGHT

_GRADE_BANDS = (
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (0, "F"),
)


def compute_score(findings: list[Finding]) -> int:
    score = 100
    for finding in findings:
        score -= SEVERITY_WEIGHT[finding.severity]
    return max(0, min(100, score))


def grade_for_score(score: int) -> str:
    for threshold, grade in _GRADE_BANDS:
        if score >= threshold:
            return grade
    return "F"  # unreachable given the 0 threshold above, kept for clarity


def compute_grade(findings: list[Finding]) -> tuple[int, str]:
    score = compute_score(findings)
    return score, grade_for_score(score)
