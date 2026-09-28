import json
from pathlib import Path

from phishtriage.detectors import run_all_detectors
from phishtriage.parser import parse_file
from phishtriage.report import build_report, to_json, to_markdown

FIXTURES = Path(__file__).parent / "fixtures"


def _report_for(name: str) -> dict:
    msg = parse_file(FIXTURES / name)
    findings = run_all_detectors(msg)
    return build_report(msg, findings)


def test_build_report_structure():
    report = _report_for("phishing_paypal.eml")
    assert report["message"]["subject"] == "Urgent: Verify your account immediately"
    assert report["summary"]["verdict"] == "malicious"
    assert len(report["findings"]) == 8
    assert report["narrative"] is None


def test_to_json_round_trips():
    report = _report_for("phishing_paypal.eml")
    parsed = json.loads(to_json(report))
    assert parsed["summary"]["risk_score"] == report["summary"]["risk_score"]


def test_to_markdown_defangs_sender_address():
    report = _report_for("phishing_paypal.eml")
    markdown = to_markdown(report)
    assert "paypa1-verify[.]com" in markdown
    assert "paypa1-verify.com" not in markdown.split("Findings")[0]


def test_to_markdown_clean_email_says_no_indicators():
    report = _report_for("benign_newsletter.eml")
    markdown = to_markdown(report)
    assert "No phishing indicators detected." in markdown
    assert "BENIGN" in markdown
