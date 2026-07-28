import json

from attack_surface_mapper.models import Finding, HostReport, OpenPort
from attack_surface_mapper import report


def _sample_report():
    return HostReport(
        host="www.example.com",
        ip="10.0.0.1",
        open_ports=[OpenPort(port=3389, service="rdp", sensitive=True)],
        findings=[
            Finding(category="tls", severity="critical", title="Expired cert", detail="oops")
        ],
        risk_score=80,
        risk_level="critical",
        errors=[],
    )


def test_render_console_contains_host_and_findings():
    text = report.render_console(_sample_report(), use_color=False)
    assert "www.example.com" in text
    assert "Expired cert" in text
    assert "3389/rdp" in text
    assert "\033[" not in text  # no ANSI codes when color disabled


def test_render_console_uses_color_when_enabled():
    text = report.render_console(_sample_report(), use_color=True)
    assert "\033[" in text


def test_render_console_clean_host_says_no_exposures():
    clean = HostReport(host="clean.example.com", ip="10.0.0.2")
    text = report.render_console(clean, use_color=False)
    assert "no exposures detected" in text


def test_render_console_shows_errors():
    errored = HostReport(host="down.example.com", ip=None, errors=["DNS resolution failed."])
    text = report.render_console(errored, use_color=False)
    assert "DNS resolution failed." in text


def test_render_summary_includes_all_hosts():
    reports = [_sample_report(), HostReport(host="clean.example.com", ip="10.0.0.2")]
    text = report.render_summary(reports, use_color=False)
    assert "www.example.com" in text
    assert "clean.example.com" in text
    assert "2 host(s)" in text


def test_write_json_round_trips(tmp_path):
    reports = [_sample_report()]
    path = tmp_path / "report.json"
    report.write_json(reports, path)

    data = json.loads(path.read_text())
    assert data[0]["host"] == "www.example.com"
    assert data[0]["risk_level"] == "critical"
    assert data[0]["findings"][0]["title"] == "Expired cert"
    assert data[0]["open_ports"][0]["port"] == 3389
