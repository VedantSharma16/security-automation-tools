"""End-to-end checks against the real specialist tools (no mocking).

These exercise the actual subprocess boundary against the bundled example
case, so a change that breaks the CLI contract of a sibling project (flag
rename, JSON shape change) is caught here rather than only in unit tests
that mock it away. Skipped automatically if a specialist project's runtime
dependency isn't installed in the current environment.
"""

from pathlib import Path

import pytest

from soc_orchestrator import agent, tools

EXAMPLE_CASE = Path(__file__).resolve().parent.parent / "examples" / "case_webserver_breach"


def test_run_log_triage_against_bundled_example():
    result = tools.run_log_triage(str(EXAMPLE_CASE / "auth.log"))
    assert result.ok is True
    assert result.severity in {"HIGH", "CRITICAL"}
    assert result.data["summary"]["total_findings"] > 0


def test_run_ioc_triage_against_bundled_example():
    result = tools.run_ioc_triage(str(EXAMPLE_CASE / "alert.txt"))
    assert result.ok is True
    assert result.severity in {"high", "critical"}
    known_malicious = [e for e in result.data["enrichment"] if e["is_known_malicious"]]
    assert known_malicious, "expected the bundled example IOCs to hit the local threat-intel feed"


def test_run_process_hunt_against_live_host():
    pytest.importorskip("psutil")
    result = tools.run_process_hunt()
    assert result.ok is True
    assert result.data["process_count"] > 0


def test_investigate_offline_produces_a_high_severity_verdict_for_the_example_case():
    pytest.importorskip("psutil")
    report = agent.investigate(str(EXAMPLE_CASE), use_llm=False)

    assert report.llm_backed is False
    assert report.overall_severity in {"high", "critical"}
    assert {t.tool for t in report.tools_invoked} == {
        "run_log_triage",
        "run_ioc_triage",
        "run_process_hunt",
    }
    assert all(t.ok for t in report.tools_invoked)
