import json

from recon_agent.agent import Action, AgentRunResult, Observation
from recon_agent.report import render_console, render_markdown, write_json
from recon_agent.vuln_kb import VulnMatch


def sample_run():
    scan_obs = Observation(Action("tcp_connect_scan", {"host": "127.0.0.1"}, "scan first"), {"open_ports": [22]})
    banner_obs = Observation(Action("grab_banner", {"host": "127.0.0.1", "port": 22}, "id the service"), {"service": "OpenSSH"})
    return AgentRunResult(
        target="127.0.0.1",
        open_ports=[22],
        fingerprints={22: {"service": "OpenSSH", "version": "7.2", "source": "banner"}},
        tls_info={},
        vuln_matches=[
            VulnMatch(
                service="OpenSSH", version="7.2", port=22, cve="CVE-2016-6210",
                severity="medium", description="username enumeration", reference="https://example.invalid",
            )
        ],
        risk="medium",
        steps_taken=2,
        completed=True,
        transcript=[scan_obs, banner_obs],
    )


def test_render_console_includes_key_fields():
    output = render_console(sample_run(), narrative="Everything looks routine.", use_color=False)
    assert "127.0.0.1" in output
    assert "MEDIUM" in output
    assert "CVE-2016-6210" in output
    assert "Everything looks routine." in output


def test_render_console_reports_no_vulns_when_none_found():
    run = sample_run()
    run.vuln_matches = []
    output = render_console(run, use_color=False)
    assert "No known-CVE matches" in output


def test_render_markdown_includes_tables_and_transcript():
    md = render_markdown(sample_run(), narrative="Summary text.")
    assert "# Recon Report: 127.0.0.1" in md
    assert "| Port | Service | Version | Source |" in md
    assert "CVE-2016-6210" in md
    assert "Summary text." in md
    assert "`tcp_connect_scan`" in md
    assert "`grab_banner`" in md


def test_write_json_produces_valid_json_with_narrative(tmp_path):
    path = tmp_path / "report.json"
    write_json(sample_run(), path, narrative="Narrative here.")
    data = json.loads(path.read_text())
    assert data["target"] == "127.0.0.1"
    assert data["narrative"] == "Narrative here."
    assert data["vuln_matches"][0]["cve"] == "CVE-2016-6210"
