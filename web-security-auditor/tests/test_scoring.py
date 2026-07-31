from webauditor.models import Finding, Severity, Status
from webauditor.scoring import compute_score, grade_for_score


def _finding(status, severity):
    return Finding("x", "X", status, severity, "msg")


def test_no_findings_is_perfect_score():
    assert compute_score([]) == 100
    assert grade_for_score(100) == "A"


def test_pass_and_info_findings_do_not_deduct():
    findings = [_finding(Status.PASS, Severity.INFO) for _ in range(5)]
    assert compute_score(findings) == 100


def test_single_critical_fail_drops_grade():
    score = compute_score([_finding(Status.FAIL, Severity.CRITICAL)])
    assert score == 70
    assert grade_for_score(score) == "C"


def test_warn_deducts_half_of_fail_weight():
    fail_score = compute_score([_finding(Status.FAIL, Severity.HIGH)])
    warn_score = compute_score([_finding(Status.WARN, Severity.HIGH)])
    assert warn_score == 100 - (100 - fail_score) // 2


def test_score_never_drops_below_zero():
    findings = [_finding(Status.FAIL, Severity.CRITICAL) for _ in range(10)]
    assert compute_score(findings) == 0
    assert grade_for_score(0) == "F"


def test_grade_thresholds():
    assert grade_for_score(95) == "A"
    assert grade_for_score(85) == "B"
    assert grade_for_score(75) == "C"
    assert grade_for_score(65) == "D"
    assert grade_for_score(59) == "F"
