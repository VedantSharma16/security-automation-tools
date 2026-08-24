from webauditor.findings import Finding, Severity
from webauditor.scoring import build_summary


def _finding(severity: Severity, id_suffix="") -> Finding:
    return Finding(
        id=f"f{id_suffix}",
        title="t",
        severity=severity,
        owasp_category="A05:2021",
        description="d",
    )


def test_no_findings_gives_zero_score_and_none_rating():
    summary = build_summary([])
    assert summary["risk_score"] == 0
    assert summary["risk_rating"] == "none"
    assert summary["highest_severity"] is None
    assert summary["total_findings"] == 0


def test_single_critical_finding_rates_critical():
    summary = build_summary([_finding(Severity.CRITICAL)])
    assert summary["risk_score"] == 50
    assert summary["risk_rating"] == "high"  # 50 >= 40 threshold, below 70


def test_two_critical_findings_rate_critical():
    summary = build_summary([_finding(Severity.CRITICAL, "1"), _finding(Severity.CRITICAL, "2")])
    assert summary["risk_score"] == 100
    assert summary["risk_rating"] == "critical"


def test_info_only_findings_score_zero():
    summary = build_summary([_finding(Severity.INFO)])
    assert summary["risk_score"] == 0
    assert summary["risk_rating"] == "none"


def test_score_caps_at_100():
    findings = [_finding(Severity.CRITICAL, str(i)) for i in range(5)]
    summary = build_summary(findings)
    assert summary["risk_score"] == 100


def test_highest_severity_tracks_max():
    findings = [_finding(Severity.LOW, "1"), _finding(Severity.HIGH, "2"), _finding(Severity.MEDIUM, "3")]
    summary = build_summary(findings)
    assert summary["highest_severity"] == "HIGH"
    assert summary["by_severity"]["HIGH"] == 1
    assert summary["by_severity"]["LOW"] == 1
    assert summary["by_severity"]["MEDIUM"] == 1
