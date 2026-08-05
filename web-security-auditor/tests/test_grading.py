import pytest

from websecaudit.findings import Finding
from websecaudit.grading import compute_score, grade_for_score, meets_minimum_grade


def _finding(severity):
    return Finding(
        id=f"test-{severity}", severity=severity, category="header",
        message="m", recommendation="r",
    )


def test_no_findings_perfect_score():
    assert compute_score([]) == 100


def test_score_decreases_by_severity_weight():
    assert compute_score([_finding("medium")]) == 92
    assert compute_score([_finding("critical")]) == 70


def test_score_never_negative():
    findings = [_finding("critical") for _ in range(10)]
    assert compute_score(findings) == 0


def test_info_findings_do_not_affect_score():
    assert compute_score([_finding("info"), _finding("info")]) == 100


@pytest.mark.parametrize(
    "score,expected",
    [(100, "A+"), (95, "A+"), (90, "A"), (85, "A"), (75, "B"), (60, "C"), (45, "D"), (10, "F"), (0, "F")],
)
def test_grade_thresholds(score, expected):
    assert grade_for_score(score) == expected


def test_meets_minimum_grade():
    assert meets_minimum_grade("A", "C") is True
    assert meets_minimum_grade("C", "C") is True
    assert meets_minimum_grade("D", "C") is False
    assert meets_minimum_grade("F", "A+") is False
