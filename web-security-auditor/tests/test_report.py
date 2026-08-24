import json

from webauditor.findings import Finding, Severity
from webauditor.report import build_report, filter_by_min_severity, render_console, to_json, to_markdown


def _findings():
    return [
        Finding(
            id="a",
            title="Missing HSTS",
            severity=Severity.HIGH,
            owasp_category="A02:2021 Cryptographic Failures",
            description="desc",
            evidence="ev",
            remediation="fix it",
        ),
        Finding(
            id="b",
            title="Missing Permissions-Policy",
            severity=Severity.INFO,
            owasp_category="A05:2021 Security Misconfiguration",
            description="desc2",
        ),
    ]


def test_build_report_sorts_by_severity_descending():
    report = build_report("https://example.com", _findings())
    severities = [f["severity"] for f in report["findings"]]
    assert severities == ["HIGH", "INFO"]
    assert report["summary"]["total_findings"] == 2


def test_filter_by_min_severity_excludes_lower():
    report = build_report("https://example.com", _findings())
    filtered = filter_by_min_severity(report, "high")
    assert len(filtered["findings"]) == 1
    assert filtered["findings"][0]["id"] == "a"


def test_to_json_roundtrips():
    report = build_report("https://example.com", _findings())
    parsed = json.loads(to_json(report))
    assert parsed["target"] == "https://example.com"
    assert len(parsed["findings"]) == 2


def test_to_markdown_contains_key_sections():
    report = build_report("https://example.com", _findings())
    md = to_markdown(report)
    assert "# Web Security Audit: https://example.com" in md
    assert "## Summary" in md
    assert "## Findings" in md
    assert "Missing HSTS" in md
    assert "**Remediation:** fix it" in md


def test_render_console_no_findings():
    report = build_report("https://example.com", [])
    output = render_console(report, use_color=False)
    assert "No findings" in output


def test_render_console_includes_narrative():
    report = build_report("https://example.com", [], narrative="All clear.")
    output = render_console(report, use_color=False)
    assert "Analyst narrative" in output
    assert "All clear." in output
