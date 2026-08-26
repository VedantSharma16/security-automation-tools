"""Aggregates findings into a single score and letter grade."""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Finding, SEVERITIES

SEVERITY_WEIGHTS = {
    "critical": 40,
    "high": 20,
    "medium": 10,
    "low": 4,
    "info": 0,
}

GRADE_THRESHOLDS = (
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (50, "D"),
    (0, "F"),
)


@dataclass
class ScoreResult:
    score: int
    grade: str
    counts: dict = field(default_factory=dict)


def score_findings(findings: list[Finding]) -> ScoreResult:
    counts = {sev: 0 for sev in SEVERITIES}
    penalty = 0
    for finding in findings:
        counts[finding.severity] += 1
        penalty += SEVERITY_WEIGHTS[finding.severity]

    score = max(0, 100 - penalty)
    grade = next(letter for threshold, letter in GRADE_THRESHOLDS if score >= threshold)
    return ScoreResult(score=score, grade=grade, counts=counts)
