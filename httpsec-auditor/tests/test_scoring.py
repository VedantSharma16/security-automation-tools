import pytest

from httpsec.models import Finding
from httpsec.scoring import score_findings


def _finding(severity: str, i: int = 0) -> Finding:
    return Finding(
        id=f"f-{severity}-{i}",
        category="headers",
        severity=severity,
        title="t",
        description="d",
        remediation="r",
    )


def test_no_findings_is_perfect_score():
    result = score_findings([])
    assert result.score == 100
    assert result.grade == "A"
    assert result.counts == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}


def test_single_critical_drops_grade():
    result = score_findings([_finding("critical")])
    assert result.score == 60
    assert result.grade == "D"


def test_info_findings_do_not_affect_score():
    result = score_findings([_finding("info"), _finding("info", 1)])
    assert result.score == 100
    assert result.grade == "A"
    assert result.counts["info"] == 2


def test_score_floors_at_zero():
    findings = [_finding("critical", i) for i in range(5)]
    result = score_findings(findings)
    assert result.score == 0
    assert result.grade == "F"


def test_grade_boundaries():
    # 2 mediums = 20 penalty -> score 80 -> should be "B" (>=80)
    result = score_findings([_finding("medium", 0), _finding("medium", 1)])
    assert result.score == 80
    assert result.grade == "B"


def test_invalid_severity_rejected():
    with pytest.raises(ValueError):
        Finding(
            id="bad",
            category="headers",
            severity="apocalyptic",
            title="t",
            description="d",
            remediation="r",
        )
