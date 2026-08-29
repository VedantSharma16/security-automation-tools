import json

from asm.findings import Finding, Severity
from asm.report import build_report, to_json, to_markdown


def _sample_report():
    findings = [
        Finding("tls", Severity.HIGH, "TLS certificate expiring imminently", "5 days left"),
        Finding("dns", Severity.INFO, "A records resolved", "1.2.3.4"),
    ]
    return build_report(
        domain="example.com",
        dns_records={"A": ["1.2.3.4"]},
        subdomains=["www.example.com"],
        http_result={"https": None, "http": None},
        tls_info={"protocol": "TLSv1.3"},
        findings=findings,
    )


def test_build_report_sorts_findings_by_severity_descending():
    report = _sample_report()
    severities = [f["severity"] for f in report["findings"]]
    assert severities == ["HIGH", "INFO"]


def test_build_report_includes_summary():
    report = _sample_report()
    assert report["summary"]["total_findings"] == 2
    assert report["summary"]["highest_severity"] == "HIGH"


def test_to_json_round_trips():
    report = _sample_report()
    parsed = json.loads(to_json(report))
    assert parsed["domain"] == "example.com"


def test_to_markdown_contains_key_sections():
    report = _sample_report()
    report["narrative"] = "Everything looks mostly fine."
    md = to_markdown(report)
    assert "# Attack Surface Report: example.com" in md
    assert "## Findings" in md
    assert "TLS certificate expiring imminently" in md
    assert "## Analyst Narrative" in md
    assert "Everything looks mostly fine." in md


def test_to_markdown_handles_no_findings():
    report = build_report("example.com", {}, [], {"https": None, "http": None}, None, [])
    md = to_markdown(report)
    assert "No findings." in md
