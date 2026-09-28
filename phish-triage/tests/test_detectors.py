from pathlib import Path

from phishtriage.detectors import run_all_detectors
from phishtriage.parser import parse_file

FIXTURES = Path(__file__).parent / "fixtures"


def test_phishing_email_trips_all_expected_detectors():
    msg = parse_file(FIXTURES / "phishing_paypal.eml")
    findings = run_all_detectors(msg)
    types = {f.type for f in findings}
    assert types == {
        "auth_failure",
        "display_name_spoof",
        "reply_to_mismatch",
        "suspicious_url",
        "link_text_mismatch",
        "dangerous_attachment",
        "urgency_language",
    }


def test_phishing_findings_carry_attack_technique_where_applicable():
    msg = parse_file(FIXTURES / "phishing_paypal.eml")
    findings = run_all_detectors(msg)
    by_type = {f.type: f for f in findings}
    assert by_type["dangerous_attachment"].attack_technique == "T1566.001 (Spearphishing Attachment)"
    assert by_type["suspicious_url"].attack_technique == "T1566.002 (Spearphishing Link)"


def test_benign_email_has_no_findings():
    msg = parse_file(FIXTURES / "benign_newsletter.eml")
    findings = run_all_detectors(msg)
    assert findings == []


def test_suspicious_shortlink_email_flags_missing_auth_and_shortener_only():
    msg = parse_file(FIXTURES / "suspicious_shortlink.eml")
    findings = run_all_detectors(msg)
    types = {f.type for f in findings}
    assert types == {"auth_results_missing", "suspicious_url"}


def test_finding_to_dict_round_trips_fields():
    msg = parse_file(FIXTURES / "phishing_paypal.eml")
    finding = run_all_detectors(msg)[0]
    d = finding.to_dict()
    assert d["type"] == finding.type
    assert d["severity"] == finding.severity.name
    assert isinstance(d["evidence"], dict)
