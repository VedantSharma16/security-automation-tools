"""Unit tests for the specialist-tool wrappers.

`_run_subprocess` is monkeypatched everywhere so these tests don't depend on
the sibling projects' own dependencies (psutil, anthropic, ...) being
installed, and run fast/deterministically. The subprocess boundary itself is
exercised separately as an integration check in test_tools_integration.py.
"""

import json
import subprocess

import pytest

from soc_orchestrator import tools


def _completed(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def test_run_log_triage_missing_file_is_reported_not_raised(tmp_path):
    result = tools.run_log_triage(str(tmp_path / "nope.log"))
    assert result.ok is False
    assert "no such file" in result.error


def test_run_log_triage_parses_json_report(tmp_path, monkeypatch):
    logfile = tmp_path / "auth.log"
    logfile.write_text("...", encoding="utf-8")
    fake_report = {
        "summary": {"total_findings": 2, "highest_severity": "HIGH", "risk_score": 45},
        "findings": [{"type": "brute_force"}],
    }
    monkeypatch.setattr(tools, "_run_subprocess", lambda args, cwd: _completed(stdout=json.dumps(fake_report)))

    result = tools.run_log_triage(str(logfile))

    assert result.ok is True
    assert result.tool == "run_log_triage"
    assert result.severity == "HIGH"
    assert "2 auth-log finding(s)" in result.summary
    assert result.data == fake_report


def test_run_log_triage_nonzero_exit_is_reported_as_failure(tmp_path, monkeypatch):
    logfile = tmp_path / "auth.log"
    logfile.write_text("...", encoding="utf-8")
    monkeypatch.setattr(
        tools, "_run_subprocess", lambda args, cwd: _completed(returncode=1, stderr="boom")
    )

    result = tools.run_log_triage(str(logfile))

    assert result.ok is False
    assert result.error == "boom"


def test_run_ioc_triage_parses_json_report(tmp_path, monkeypatch):
    alert_file = tmp_path / "alert.txt"
    alert_file.write_text("...", encoding="utf-8")
    fake_report = {
        "severity": "critical",
        "indicators": [{"value": "1.2.3.4"}],
        "enrichment": [{"value": "1.2.3.4", "is_known_malicious": True}],
        "matched_techniques": [],
    }
    monkeypatch.setattr(tools, "_run_subprocess", lambda args, cwd: _completed(stdout=json.dumps(fake_report)))

    result = tools.run_ioc_triage(str(alert_file))

    assert result.ok is True
    assert result.severity == "critical"
    assert "1 matched known-malicious" in result.summary


def test_run_ioc_triage_missing_file_is_reported_not_raised(tmp_path):
    result = tools.run_ioc_triage(str(tmp_path / "nope.txt"))
    assert result.ok is False


def test_run_process_hunt_reads_json_out_file(monkeypatch, tmp_path):
    fake_report = {"highest_severity": "critical", "finding_count": 1, "process_count": 42}

    def fake_run_subprocess(args, cwd):
        out_path = args[args.index("--json-out") + 1]
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(fake_report, fh)
        return _completed(returncode=1)  # process-threat-hunter exits 1 when it has findings

    monkeypatch.setattr(tools, "_run_subprocess", fake_run_subprocess)

    result = tools.run_process_hunt()

    assert result.ok is True
    assert result.severity == "critical"
    assert "1 suspicious process finding(s)" in result.summary


def test_run_process_hunt_renders_no_findings_severity_as_none_not_python_none(monkeypatch, tmp_path):
    fake_report = {"highest_severity": None, "finding_count": 0, "process_count": 10}

    def fake_run_subprocess(args, cwd):
        out_path = args[args.index("--json-out") + 1]
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(fake_report, fh)
        return _completed(returncode=0)

    monkeypatch.setattr(tools, "_run_subprocess", fake_run_subprocess)

    result = tools.run_process_hunt()

    assert result.severity is None
    assert "highest severity none." in result.summary


def test_run_process_hunt_hard_failure_is_reported(monkeypatch):
    monkeypatch.setattr(
        tools, "_run_subprocess", lambda args, cwd: _completed(returncode=2, stderr="crashed")
    )
    result = tools.run_process_hunt()
    assert result.ok is False
    assert result.error == "crashed"


def test_tool_result_to_dict_round_trips():
    result = tools.ToolResult(tool="x", ok=True, severity="low", summary="s", data={"a": 1})
    assert result.to_dict() == {
        "tool": "x",
        "ok": True,
        "severity": "low",
        "summary": "s",
        "data": {"a": 1},
        "error": None,
    }


def test_dispatch_and_specs_agree_on_tool_names():
    assert set(tools.DISPATCH.keys()) == {spec["name"] for spec in tools.TOOL_SPECS}
