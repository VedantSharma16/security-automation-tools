from websec_auditor.findings import Finding
from websec_auditor.scoring import compute_grade, compute_score, grade_for_score


def mk(severity):
    return Finding(id=f"x-{severity}", severity=severity, category="test", message="m")


def test_no_findings_is_perfect_score():
    assert compute_score([]) == 100
    assert grade_for_score(100) == "A"


def test_info_findings_do_not_reduce_score():
    assert compute_score([mk("info"), mk("info")]) == 100


def test_score_never_goes_below_zero():
    findings = [mk("critical") for _ in range(10)]
    assert compute_score(findings) == 0


def test_grade_bands():
    assert grade_for_score(95) == "A"
    assert grade_for_score(90) == "A"
    assert grade_for_score(85) == "B"
    assert grade_for_score(75) == "C"
    assert grade_for_score(65) == "D"
    assert grade_for_score(10) == "F"


def test_compute_grade_combines_score_and_grade():
    score, grade = compute_grade([mk("high")])
    assert score == 85
    assert grade == "B"
