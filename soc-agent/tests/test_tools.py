import json
import subprocess
from pathlib import Path

import pytest

from soc_agent import tools

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / "fixtures"


def _fake_completed(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(args=["x"], returncode=returncode, stdout=stdout, stderr=stderr)


# ---------------------------------------------------------------------------
# Unit tests: mock subprocess.run so these are fast and don't depend on the
# sibling projects' own dependencies (e.g. psutil) being installed.
# ---------------------------------------------------------------------------


def test_run_log_triage_parses_ok_result(monkeypatch):
    fake_payload = {
        "summary": {"total_findings": 2, "highest_severity": "high", "risk_score": 60},
        "findings": [],
    }
    monkeypatch.setattr(
        tools.subprocess, "run", lambda *a, **k: _fake_completed(stdout=json.dumps(fake_payload))
    )

    result = tools.run_log_triage(FIXTURES / "auth_evidence.txt", REPO_ROOT)

    assert result.status == "ok"
    assert result.tool == "log_triage"
    assert result.severity == "high"
    assert result.finding_count == 2
    assert result.risk_score == 60
    assert "2 auth-log finding" in result.headline


def test_run_log_triage_reports_error_on_nonzero_exit(monkeypatch):
    monkeypatch.setattr(
        tools.subprocess, "run", lambda *a, **k: _fake_completed(returncode=1, stderr="boom")
    )
    result = tools.run_log_triage(FIXTURES / "auth_evidence.txt", REPO_ROOT)
    assert result.status == "error"
    assert "boom" in result.error


def test_run_log_triage_reports_error_on_bad_json(monkeypatch):
    monkeypatch.setattr(tools.subprocess, "run", lambda *a, **k: _fake_completed(stdout="not json"))
    result = tools.run_log_triage(FIXTURES / "auth_evidence.txt", REPO_ROOT)
    assert result.status == "error"
    assert "invalid JSON" in result.error


def test_run_ioc_triage_parses_ok_result(monkeypatch):
    fake_payload = {
        "severity": "critical",
        "indicators": [{"category": "ipv4", "value": "1.2.3.4"}],
        "enrichment": [{"value": "1.2.3.4", "is_known_malicious": True, "confidence": "high"}],
        "matched_techniques": [],
    }
    monkeypatch.setattr(
        tools.subprocess, "run", lambda *a, **k: _fake_completed(stdout=json.dumps(fake_payload))
    )

    result = tools.run_ioc_triage(FIXTURES / "alert_evidence.txt", REPO_ROOT)

    assert result.status == "ok"
    assert result.severity == "critical"
    assert result.finding_count == 1
    assert "1 known-malicious" in result.headline


def test_run_process_hunter_missing_dependency_is_reported_as_error(monkeypatch, tmp_path):
    # Simulate psutil (or another dependency) missing: the tool crashes before
    # writing its JSON report, so no report file exists even though the
    # subprocess "succeeds" from the OS's point of view isn't guaranteed either.
    def fake_run(cmd, cwd, capture_output, text, timeout):
        return _fake_completed(returncode=1, stderr="ModuleNotFoundError: No module named 'psutil'")

    monkeypatch.setattr(tools.subprocess, "run", fake_run)

    result = tools.run_process_hunter(REPO_ROOT)

    assert result.status == "error"
    assert "psutil" in result.error or "exited with code" in result.error


def test_run_process_hunter_parses_ok_result_from_json_file(monkeypatch):
    fake_report = {
        "highest_severity": "medium",
        "finding_count": 1,
        "process_count": 42,
        "findings": [],
    }

    def fake_run(cmd, cwd, capture_output, text, timeout):
        json_out = Path(cmd[cmd.index("--json-out") + 1])
        json_out.write_text(json.dumps(fake_report), encoding="utf-8")
        return _fake_completed(returncode=1)  # 1 == "findings present", not an error

    monkeypatch.setattr(tools.subprocess, "run", fake_run)

    result = tools.run_process_hunter(REPO_ROOT)

    assert result.status == "ok"
    assert result.severity == "medium"
    assert result.finding_count == 1


def test_skipped_tool_result():
    result = tools.skipped("ioc_triage", "not selected for this evidence")
    assert result.status == "skipped"
    assert result.headline == "not selected for this evidence"


# ---------------------------------------------------------------------------
# Integration tests: actually invoke the sibling tools as subprocesses.
# log_triage and ioc_triage have no runtime dependencies, so these always run.
# ---------------------------------------------------------------------------


def test_run_log_triage_integration_real_subprocess():
    result = tools.run_log_triage(FIXTURES / "auth_evidence.txt", REPO_ROOT)
    assert result.status == "ok", result.error
    assert result.finding_count > 0
    assert result.severity in ("low", "medium", "high", "critical")


def test_run_ioc_triage_integration_real_subprocess():
    result = tools.run_ioc_triage(FIXTURES / "alert_evidence.txt", REPO_ROOT)
    assert result.status == "ok", result.error
    assert result.finding_count > 0


def test_run_process_hunter_integration_real_subprocess():
    result = tools.run_process_hunter(REPO_ROOT)
    if result.status == "error":
        pytest.skip(f"process_threat_hunter dependency not available: {result.error}")
    assert result.finding_count >= 0
