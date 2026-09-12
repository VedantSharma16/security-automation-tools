from webrecon.findings import Finding
from webrecon.scoring import assess_risk


def _finding(severity, suffix=""):
    return Finding(
        id=f"f-{severity}{suffix}",
        category="headers",
        severity=severity,
        title="t",
        detail="d",
        recommendation="r",
    )


def test_no_findings_is_zero_score_info():
    risk = assess_risk([])
    assert risk.score == 0
    assert risk.overall_severity == "info"


def test_single_critical_dominates():
    risk = assess_risk([_finding("critical")])
    assert risk.overall_severity == "critical"
    assert risk.score >= 60


def test_single_low_stays_low_severity_low_score():
    risk = assess_risk([_finding("low")])
    assert risk.overall_severity == "low"
    assert 0 < risk.score <= 15


def test_repeated_same_severity_has_diminishing_returns():
    one = assess_risk([_finding("high", "a")])
    two = assess_risk([_finding("high", "a"), _finding("high", "b")])
    three = assess_risk([_finding("high", "a"), _finding("high", "b"), _finding("high", "c")])
    # Each additional same-severity finding adds less than the previous one.
    assert (two.score - one.score) > (three.score - two.score) >= 0


def test_score_never_exceeds_100():
    findings = [_finding("critical", str(i)) for i in range(10)]
    risk = assess_risk(findings)
    assert risk.score == 100


def test_severity_counts_track_each_bucket():
    findings = [_finding("high"), _finding("high", "2"), _finding("low")]
    risk = assess_risk(findings)
    assert risk.severity_counts["high"] == 2
    assert risk.severity_counts["low"] == 1
    assert risk.severity_counts["critical"] == 0
