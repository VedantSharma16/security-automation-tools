from webaudit.models import CheckResult
from webaudit.report import build_report, compute_score, grade_for_score


def _result(status, severity):
    return CheckResult("id", "headers", status, severity, "Title", "detail", None)


def test_score_with_no_findings_is_100():
    assert compute_score([_result("pass", "info")]) == 100


def test_score_deducts_for_fail_and_warn_only():
    results = [_result("fail", "high"), _result("warn", "medium"), _result("pass", "info")]
    assert compute_score(results) == 100 - 15 - 8


def test_score_floors_at_zero():
    results = [_result("fail", "critical") for _ in range(10)]
    assert compute_score(results) == 0


def test_grade_thresholds():
    assert grade_for_score(95) == "A"
    assert grade_for_score(85) == "B"
    assert grade_for_score(75) == "C"
    assert grade_for_score(65) == "D"
    assert grade_for_score(40) == "F"


def test_build_report_summary_and_ordering():
    results = [
        _result("pass", "info"),
        _result("fail", "critical"),
        _result("warn", "low"),
    ]
    report = build_report("https://example.com", results)

    assert report["target"] == "https://example.com"
    assert report["summary"] == {"pass": 1, "warn": 1, "fail": 1, "info": 0}
    # fail-severity checks should sort before warn, which sorts before pass
    assert [c["status"] for c in report["checks"]] == ["fail", "warn", "pass"]
