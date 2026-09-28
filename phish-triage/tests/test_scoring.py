from phishtriage.detectors import Finding
from phishtriage.scoring import Severity, build_summary


def make_finding(severity: Severity) -> Finding:
    return Finding(
        type="test",
        severity=severity,
        title="t",
        description="d",
        evidence={},
    )


def test_build_summary_empty_findings_is_benign():
    summary = build_summary([])
    assert summary["total_findings"] == 0
    assert summary["risk_score"] == 0
    assert summary["highest_severity"] is None
    assert summary["verdict"] == "benign"


def test_build_summary_single_medium_is_suspicious():
    summary = build_summary([make_finding(Severity.MEDIUM)])
    assert summary["verdict"] == "suspicious"
    assert summary["risk_score"] == 15


def test_build_summary_critical_is_malicious():
    summary = build_summary([make_finding(Severity.CRITICAL)])
    assert summary["verdict"] == "malicious"
    assert summary["highest_severity"] == "CRITICAL"


def test_build_summary_risk_score_caps_at_100():
    summary = build_summary([make_finding(Severity.CRITICAL) for _ in range(5)])
    assert summary["risk_score"] == 100


def test_build_summary_by_severity_breakdown():
    summary = build_summary([make_finding(Severity.LOW), make_finding(Severity.LOW), make_finding(Severity.HIGH)])
    assert summary["by_severity"] == {"LOW": 2, "MEDIUM": 0, "HIGH": 1, "CRITICAL": 0}
