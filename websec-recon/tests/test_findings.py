import pytest

from recon.findings import Finding, score_findings


def test_finding_rejects_invalid_severity():
    with pytest.raises(ValueError):
        Finding(category="ports", title="x", severity="nope", description="d")


def test_finding_to_dict_roundtrip():
    f = Finding(
        category="tls",
        title="Expiring cert",
        severity="high",
        description="d",
        recommendation="r",
        evidence={"days_left": 3},
    )
    d = f.to_dict()
    assert d == {
        "category": "tls",
        "title": "Expiring cert",
        "severity": "high",
        "description": "d",
        "recommendation": "r",
        "evidence": {"days_left": 3},
    }


def test_score_findings_empty_is_clean():
    result = score_findings([])
    assert result == {
        "score": 0,
        "label": "clean",
        "counts": {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0},
    }


def test_score_findings_critical_always_labeled_critical():
    findings = [Finding(category="tls", title="x", severity="critical", description="d")]
    result = score_findings(findings)
    assert result["label"] == "critical"
    assert result["score"] > 0


def test_score_findings_caps_at_100():
    findings = [
        Finding(category="ports", title=f"f{i}", severity="critical", description="d")
        for i in range(5)
    ]
    result = score_findings(findings)
    assert result["score"] == 100


def test_score_findings_many_low_severity_stays_low_label():
    findings = [
        Finding(category="dns", title=f"f{i}", severity="info", description="d")
        for i in range(50)
    ]
    result = score_findings(findings)
    assert result["label"] == "clean"
    assert result["score"] == 0
