from __future__ import annotations

from asmapper.models import Finding, Severity
from asmapper.scoring import build_summary


def _f(severity: Severity, category: str = "headers") -> Finding:
    return Finding(id=f"x-{severity.name}-{category}", title="t", severity=severity, detail="d", category=category)


def test_no_findings_is_clean():
    summary = build_summary([])
    assert summary["risk_score"] == 0
    assert summary["rating"] == "clean"
    assert summary["highest_severity"] is None


def test_single_low_finding_rates_low():
    summary = build_summary([_f(Severity.LOW)])
    assert summary["risk_score"] == 5
    assert summary["rating"] == "low"


def test_critical_finding_rates_high_or_critical_by_score():
    summary = build_summary([_f(Severity.CRITICAL)])
    assert summary["risk_score"] == 50
    assert summary["rating"] == "high"


def test_multiple_criticals_cap_at_100_and_rate_critical():
    summary = build_summary([_f(Severity.CRITICAL), _f(Severity.CRITICAL), _f(Severity.HIGH)])
    assert summary["risk_score"] == 100
    assert summary["rating"] == "critical"


def test_by_severity_and_by_category_breakdowns():
    findings = [_f(Severity.LOW, "headers"), _f(Severity.MEDIUM, "exposure"), _f(Severity.LOW, "robots")]
    summary = build_summary(findings)
    assert summary["by_severity"]["LOW"] == 2
    assert summary["by_severity"]["MEDIUM"] == 1
    assert summary["by_category"] == {"headers": 1, "exposure": 1, "robots": 1}
    assert summary["highest_severity"] == "MEDIUM"
