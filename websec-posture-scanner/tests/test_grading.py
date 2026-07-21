from webscan.grading import compute_score, grade_for_score
from webscan.models import Finding


def _finding(severity: str) -> Finding:
    return Finding(
        id=f"test-{severity}",
        title="test",
        severity=severity,
        category="headers",
        description="d",
        remediation="r",
    )


def test_no_findings_is_perfect_score():
    assert compute_score([]) == 100
    assert grade_for_score(100) == "A"


def test_score_deducts_by_severity_weight():
    score = compute_score([_finding("medium")])
    assert score == 93


def test_score_floors_at_zero():
    score = compute_score([_finding("critical")] * 10)
    assert score == 0


def test_info_findings_do_not_affect_score():
    assert compute_score([_finding("info"), _finding("info")]) == 100


def test_grade_boundaries():
    assert grade_for_score(90) == "A"
    assert grade_for_score(89) == "B"
    assert grade_for_score(75) == "B"
    assert grade_for_score(74) == "C"
    assert grade_for_score(60) == "C"
    assert grade_for_score(59) == "D"
    assert grade_for_score(40) == "D"
    assert grade_for_score(39) == "F"
    assert grade_for_score(0) == "F"
