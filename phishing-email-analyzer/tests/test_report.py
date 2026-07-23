import json
from pathlib import Path

from phishtriage.heuristics import run_all_heuristics
from phishtriage.parser import parse_file
from phishtriage.report import build_report, to_json, to_markdown

FIXTURES = Path(__file__).parent / "fixtures"


def test_build_report_includes_sender_and_summary():
    email = parse_file(FIXTURES / "phishing_paypal.eml")
    findings = run_all_heuristics(email)
    report = build_report(FIXTURES / "phishing_paypal.eml", email, findings)

    assert report["sender"]["address"] == "security@paypa1-secure.com"
    assert report["summary"]["verdict"] == "likely_phishing"
    assert len(report["findings"]) == len(findings)


def test_to_json_round_trips():
    email = parse_file(FIXTURES / "clean_newsletter.eml")
    report = build_report(FIXTURES / "clean_newsletter.eml", email, [])
    parsed = json.loads(to_json(report))
    assert parsed["summary"]["verdict"] == "benign"


def test_to_markdown_contains_key_sections():
    email = parse_file(FIXTURES / "phishing_paypal.eml")
    findings = run_all_heuristics(email)
    report = build_report(FIXTURES / "phishing_paypal.eml", email, findings)
    report["narrative"] = "Test narrative."
    markdown = to_markdown(report)

    assert "# Phishing Triage Report" in markdown
    assert "## Summary" in markdown
    assert "## Findings" in markdown
    assert "## Analyst Narrative" in markdown
    assert "LIKELY PHISHING" in markdown


def test_to_markdown_reports_no_findings_for_clean_email():
    email = parse_file(FIXTURES / "clean_newsletter.eml")
    report = build_report(FIXTURES / "clean_newsletter.eml", email, [])
    markdown = to_markdown(report)
    assert "No phishing indicators detected." in markdown
