from phishscope.checks import Finding
from phishscope.scoring import score_findings, verdict_for


def F(check, sev="medium", score=10):
    return Finding(check, check, sev, score)


def test_verdict_bands():
    assert [verdict_for(s) for s in (0, 19, 20, 44, 45, 69, 70, 100)] == [
        "clean", "clean", "suspicious", "suspicious",
        "likely_phishing", "likely_phishing", "malicious", "malicious",
    ]


def test_empty_is_clean():
    s = score_findings([])
    assert s["risk_score"] == 0 and s["verdict"] == "clean" and s["highest_severity"] == "none"


def test_repeated_check_has_diminishing_returns():
    s = score_findings([F("suspicious_link", score=12)] * 5)
    assert s["risk_score"] == 12 + 0.25 * 12 * 4


def test_score_capped_at_100():
    findings = [F(f"c{i}", score=40) for i in range(5)]
    assert score_findings(findings)["risk_score"] == 100


def test_critical_floors_to_likely_phishing():
    s = score_findings([F("attachment_executable", "critical", 5)])
    assert s["risk_score"] == 45 and s["verdict"] == "likely_phishing"


def test_trusted_sender_halves_content_only_signals():
    findings = [F("credential_lure", score=16), F("urgency_pressure", score=8)]
    assert score_findings(findings)["risk_score"] == 24
    assert score_findings(findings, trusted_sender=True)["risk_score"] == 12
