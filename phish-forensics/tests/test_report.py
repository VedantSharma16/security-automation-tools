import json
from pathlib import Path

from phish_forensics.authresults import parse_authentication_results
from phish_forensics.heuristics import run_all
from phish_forensics.parser import parse_eml
from phish_forensics.report import build_report, to_json, to_markdown

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _report_for(fixture_name: str) -> dict:
    email = parse_eml(FIXTURES / fixture_name)
    auth = parse_authentication_results(email.auth_results_headers)
    findings = run_all(email, auth)
    return build_report(email, auth, findings)


def test_report_structure():
    report = _report_for("phishing_paypal_bec.eml")
    assert report["message"]["from_domain"] == "paypa1-support.com"
    assert report["auth_results"]["evaluated"] is True
    assert report["auth_results"]["dmarc"] == "fail"
    assert isinstance(report["findings"], list) and report["findings"]
    assert report["summary"]["total_findings"] == len(report["findings"])
    assert report["narrative"] is None


def test_iocs_are_defanged_in_report():
    report = _report_for("phishing_paypal_bec.eml")
    iocs = report["iocs"]
    assert all("hxxp" in u or "[.]" in u for u in iocs["urls"])
    assert all("http://" not in u and "https://" not in u for u in iocs["urls"])
    assert any("[.]" in ip for ip in iocs["ips"])
    assert iocs["attachment_hashes"][0]["filename"] == "invoice.pdf.exe"
    assert len(iocs["attachment_hashes"][0]["sha256"]) == 64


def test_to_json_round_trips():
    report = _report_for("benign_newsletter.eml")
    parsed = json.loads(to_json(report))
    assert parsed["message"]["from_addr"] == "news@example.com"


def test_to_markdown_contains_key_sections():
    report = _report_for("phishing_paypal_bec.eml")
    md = to_markdown(report)
    assert "# Phishing Triage Report" in md
    assert "## Authentication" in md
    assert "## Summary" in md
    assert "## Findings" in md
    assert "## Extracted IOCs (defanged)" in md


def test_to_markdown_handles_no_findings():
    report = _report_for("benign_newsletter.eml")
    md = to_markdown(report)
    assert "## Findings" in md
