from datetime import datetime, timezone

from recon_assistant.fingerprint import Finding
from recon_assistant.report import build_report, filter_by_min_severity, render_json, render_markdown
from recon_assistant.scanner import PortResult

SCANNED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)


def sample_report():
    port_results = [
        PortResult(port=22, open=True, banner="SSH-2.0-OpenSSH_9.6"),
        PortResult(port=80, open=False),
        PortResult(port=6379, open=True, banner=""),
    ]
    findings = [
        Finding(
            type="exposed_database",
            severity="high",
            port=6379,
            title="Redis reachable",
            detail="d",
            recommendation="r",
        ),
    ]
    return build_report("10.0.0.5", "10.0.0.5", port_results, findings, scanned_at=SCANNED_AT)


def test_build_report_summary():
    report = sample_report()
    assert report["ports_scanned"] == 3
    assert report["summary"]["open_port_count"] == 2
    assert report["summary"]["total_findings"] == 1
    assert report["summary"]["highest_severity"] == "high"
    assert report["summary"]["risk_score"] == 20


def test_filter_by_min_severity_drops_lower_findings():
    report = sample_report()
    filtered = filter_by_min_severity(report, "critical")
    assert filtered["findings"] == []
    assert filtered["summary"]["highest_severity"] == "none"
    # original report object must not be mutated
    assert report["summary"]["total_findings"] == 1


def test_render_json_round_trips():
    import json

    report = sample_report()
    parsed = json.loads(render_json(report))
    assert parsed["target"] == "10.0.0.5"


def test_render_markdown_includes_key_sections():
    report = sample_report()
    md = render_markdown(report, narrative="Test narrative.")
    assert "# Recon Report" in md
    assert "## Open ports" in md
    assert "## Findings" in md
    assert "Redis reachable" in md
    assert "Test narrative." in md
