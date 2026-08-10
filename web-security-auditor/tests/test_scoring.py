from webauditor.findings import Finding, Severity
from webauditor.scoring import build_summary


def make_finding(severity, id_="F1"):
    return Finding(
        id=id_, title="t", severity=severity, category="c",
        description="d", recommendation="r",
    )


def test_no_findings_is_good_rating_zero_score():
    summary = build_summary([])
    assert summary["risk_score"] == 0
    assert summary["risk_rating"] == "GOOD"
    assert summary["highest_severity"] is None
    assert summary["total_findings"] == 0


def test_single_critical_pushes_rating_to_critical():
    summary = build_summary([make_finding(Severity.CRITICAL)])
    assert summary["risk_rating"] == "CRITICAL"
    assert summary["highest_severity"] == "CRITICAL"


def test_score_is_capped_at_100():
    findings = [make_finding(Severity.CRITICAL, f"F{i}") for i in range(10)]
    summary = build_summary(findings)
    assert summary["risk_score"] == 100


def test_severity_breakdown_counts_each_bucket():
    findings = [
        make_finding(Severity.LOW, "F1"),
        make_finding(Severity.LOW, "F2"),
        make_finding(Severity.HIGH, "F3"),
    ]
    summary = build_summary(findings)
    assert summary["by_severity"]["LOW"] == 2
    assert summary["by_severity"]["HIGH"] == 1
    assert summary["by_severity"]["CRITICAL"] == 0
    assert summary["total_findings"] == 3


def test_info_only_findings_stay_good_rating():
    summary = build_summary([make_finding(Severity.INFO)])
    assert summary["risk_score"] == 0
    assert summary["risk_rating"] == "GOOD"


def test_highest_severity_reflects_worst_finding_regardless_of_order():
    findings = [
        make_finding(Severity.LOW, "F1"),
        make_finding(Severity.CRITICAL, "F2"),
        make_finding(Severity.MEDIUM, "F3"),
    ]
    summary = build_summary(findings)
    assert summary["highest_severity"] == "CRITICAL"
