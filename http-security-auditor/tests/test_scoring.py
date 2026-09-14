from http_audit.report import Finding
from http_audit.scoring import grade_for_score, score_findings


def test_no_findings_scores_100_grade_a():
    assert score_findings([]) == 100
    assert grade_for_score(100) == "A"


def test_pass_and_info_findings_do_not_penalize():
    findings = [
        Finding("headers", "x", "pass", "ok"),
        Finding("headers", "y", "info", "fyi"),
    ]
    assert score_findings(findings) == 100


def test_penalties_stack_and_grade_thresholds():
    findings = [Finding("headers", "x", "critical", "bad")]
    score = score_findings(findings)
    assert score == 65
    assert grade_for_score(score) == "D"


def test_score_never_goes_below_zero():
    findings = [Finding("headers", f"x{i}", "critical", "bad") for i in range(10)]
    assert score_findings(findings) == 0
    assert grade_for_score(0) == "F"


def test_grade_boundaries():
    assert grade_for_score(90) == "A"
    assert grade_for_score(89) == "B"
    assert grade_for_score(80) == "B"
    assert grade_for_score(79) == "C"
    assert grade_for_score(60) == "D"
    assert grade_for_score(59) == "F"
