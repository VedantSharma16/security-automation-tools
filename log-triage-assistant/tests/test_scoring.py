from datetime import datetime

from logtriage.detectors import Finding
from logtriage.scoring import Severity, build_summary

NOW = datetime(2026, 1, 10)


def make_finding(severity: Severity) -> Finding:
    return Finding(
        type="test",
        severity=severity,
        title="t",
        description="d",
        evidence={},
        first_seen=NOW,
        last_seen=NOW,
    )


def test_empty_findings_yields_zero_score_and_no_highest():
    summary = build_summary([])
    assert summary["risk_score"] == 0
    assert summary["highest_severity"] is None
    assert summary["total_findings"] == 0
    assert all(v == 0 for v in summary["by_severity"].values())


def test_summary_counts_by_severity():
    findings = [make_finding(Severity.LOW), make_finding(Severity.LOW), make_finding(Severity.CRITICAL)]
    summary = build_summary(findings)
    assert summary["total_findings"] == 3
    assert summary["by_severity"]["LOW"] == 2
    assert summary["by_severity"]["CRITICAL"] == 1
    assert summary["highest_severity"] == "CRITICAL"


def test_risk_score_caps_at_100():
    findings = [make_finding(Severity.CRITICAL) for _ in range(5)]  # 5 * 50 = 250
    summary = build_summary(findings)
    assert summary["risk_score"] == 100
