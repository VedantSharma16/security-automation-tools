from phishtriage.heuristics import Finding
from phishtriage.scoring import Severity, build_summary


def test_empty_findings_yield_benign_verdict():
    summary = build_summary([])
    assert summary["total_findings"] == 0
    assert summary["risk_score"] == 0
    assert summary["highest_severity"] is None
    assert summary["verdict"] == "benign"


def test_single_low_finding_stays_benign():
    findings = [Finding(type="urgency_language", severity=Severity.LOW, title="t", description="d")]
    summary = build_summary(findings)
    assert summary["risk_score"] == 5
    assert summary["verdict"] == "benign"


def test_high_findings_reach_suspicious_or_worse():
    findings = [Finding(type="x", severity=Severity.HIGH, title="t", description="d")]
    summary = build_summary(findings)
    assert summary["risk_score"] == 30
    assert summary["verdict"] == "suspicious"


def test_multiple_critical_findings_reach_likely_phishing_and_cap_at_100():
    findings = [
        Finding(type="a", severity=Severity.CRITICAL, title="t", description="d"),
        Finding(type="b", severity=Severity.CRITICAL, title="t", description="d"),
        Finding(type="c", severity=Severity.CRITICAL, title="t", description="d"),
    ]
    summary = build_summary(findings)
    assert summary["risk_score"] == 100
    assert summary["highest_severity"] == "CRITICAL"
    assert summary["verdict"] == "likely_phishing"
    assert summary["by_severity"]["CRITICAL"] == 3
