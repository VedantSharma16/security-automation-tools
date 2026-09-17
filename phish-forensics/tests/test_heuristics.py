from pathlib import Path

from phish_forensics.authresults import parse_authentication_results
from phish_forensics.heuristics import run_all
from phish_forensics.parser import parse_eml
from phish_forensics.scoring import Severity, build_summary

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _analyze(fixture_name: str):
    email = parse_eml(FIXTURES / fixture_name)
    auth = parse_authentication_results(email.auth_results_headers)
    return email, auth, run_all(email, auth)


def test_phishing_fixture_trips_many_rules():
    _, _, findings = _analyze("phishing_paypal_bec.eml")
    ids = {f.id for f in findings}

    assert "reply_to_mismatch" in ids
    assert "display_name_spoof" in ids
    assert "lookalike_sender_domain" in ids
    assert "auth_failure" in ids
    assert "anchor_href_mismatch" in ids
    assert "url_shortener" in ids
    assert "double_extension_attachment" in ids
    assert "urgency_language" in ids

    summary = build_summary(findings)
    assert summary["highest_severity"] == "CRITICAL"
    assert summary["risk_score"] >= 80


def test_benign_fixture_is_quiet():
    _, _, findings = _analyze("benign_newsletter.eml")
    ids = {f.id for f in findings}

    # A well-authenticated, self-consistent newsletter shouldn't trip any
    # sender-spoofing, auth-failure, or malicious-link rules.
    assert "reply_to_mismatch" not in ids
    assert "return_path_mismatch" not in ids
    assert "display_name_spoof" not in ids
    assert "lookalike_sender_domain" not in ids
    assert "auth_failure" not in ids
    assert "ip_literal_url" not in ids
    assert "anchor_href_mismatch" not in ids

    summary = build_summary(findings)
    assert summary["highest_severity"] in (None, "LOW")


def test_severity_ordering_drives_highest_severity():
    from phish_forensics.heuristics import Finding

    findings = [
        Finding(id="a", severity=Severity.LOW, title="a", detail="a"),
        Finding(id="b", severity=Severity.CRITICAL, title="b", detail="b"),
        Finding(id="c", severity=Severity.MEDIUM, title="c", detail="c"),
    ]
    summary = build_summary(findings)
    assert summary["highest_severity"] == "CRITICAL"
    assert summary["total_findings"] == 3
    assert summary["by_severity"]["CRITICAL"] == 1


def test_no_findings_yields_no_highest_severity():
    summary = build_summary([])
    assert summary["highest_severity"] is None
    assert summary["risk_score"] == 0
