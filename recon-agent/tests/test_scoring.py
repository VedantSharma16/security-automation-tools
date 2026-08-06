from recon_agent.models import Finding
from recon_agent.scoring import grade_for_score, score_findings


def make_finding(severity: str) -> Finding:
    return Finding(tool="test", severity=severity, title="t", detail="d", recommendation="r")


def test_score_findings_no_findings_is_perfect():
    assert score_findings([]) == 100


def test_score_findings_subtracts_by_severity():
    findings = [make_finding("critical"), make_finding("low")]
    assert score_findings(findings) == 100 - 30 - 3


def test_score_findings_floors_at_zero():
    findings = [make_finding("critical") for _ in range(10)]
    assert score_findings(findings) == 0


def test_grade_thresholds():
    assert grade_for_score(100) == "A"
    assert grade_for_score(90) == "A"
    assert grade_for_score(89) == "B"
    assert grade_for_score(75) == "B"
    assert grade_for_score(74) == "C"
    assert grade_for_score(60) == "C"
    assert grade_for_score(59) == "D"
    assert grade_for_score(40) == "D"
    assert grade_for_score(39) == "F"
    assert grade_for_score(0) == "F"
