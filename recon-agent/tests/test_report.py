from __future__ import annotations

from recon_agent.agent import ReconReport
from recon_agent.findings import Finding
from recon_agent.report import render_human


def test_render_human_includes_key_sections():
    report = ReconReport(
        target="example.com",
        agent_backed=True,
        steps_taken=2,
        tool_results={"dns_lookup": [{"domain": "example.com"}], "http_probe": [{"host": "example.com"}]},
        findings=[Finding("high", "weak-tls-protocol", "example.com negotiated outdated protocol TLSv1.1.")],
        severity="high",
        narrative="Attack surface summary here.",
    )

    text = render_human(report)

    assert "example.com" in text
    assert "HIGH" in text
    assert "agentic (LLM tool-use loop)" in text
    assert "weak-tls-protocol" in text
    assert "dns_lookup x1" in text
    assert "Attack surface summary here." in text


def test_render_human_handles_no_findings():
    report = ReconReport(target="clean.example.com", agent_backed=False, steps_taken=5, narrative="All clear.")
    text = render_human(report)
    assert "(none)" in text
    assert "offline deterministic pipeline" in text
