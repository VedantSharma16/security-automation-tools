from recon_assistant.scoring import highest_severity, meets_min_severity, risk_score


def test_highest_severity_none_when_empty():
    assert highest_severity([]) == "none"


def test_highest_severity_picks_max():
    findings = [{"severity": "low"}, {"severity": "critical"}, {"severity": "medium"}]
    assert highest_severity(findings) == "critical"


def test_risk_score_sums_weights_and_caps_at_100():
    findings = [{"severity": "critical"}] * 5
    assert risk_score(findings) == 100


def test_risk_score_zero_when_no_findings():
    assert risk_score([]) == 0


def test_meets_min_severity():
    assert meets_min_severity("high", "medium") is True
    assert meets_min_severity("low", "medium") is False
    assert meets_min_severity("medium", "medium") is True
