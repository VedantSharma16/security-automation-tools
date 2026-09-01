import json

import pytest

from websec_auditor import cli
from websec_auditor.audit import AuditResult
from websec_auditor.findings import Finding


def make_result(findings=None, fetch_error=None):
    return AuditResult(
        url="https://example.com/",
        final_url="https://example.com/",
        status=200,
        is_https=True,
        findings=findings or [],
        technologies=[],
        score=100,
        grade="A",
        fetch_error=fetch_error,
    )


def test_scan_clean_result_exits_zero(monkeypatch, capsys):
    monkeypatch.setattr(cli, "run_audit", lambda *a, **k: make_result())
    code = cli.main(["scan", "https://example.com"])
    assert code == cli.EXIT_CLEAN
    out = capsys.readouterr().out
    assert "Grade:** A" in out


def test_scan_fetch_error_exits_with_error_code(monkeypatch, capsys):
    monkeypatch.setattr(cli, "run_audit", lambda *a, **k: make_result(fetch_error="down"))
    code = cli.main(["scan", "https://example.com"])
    assert code == cli.EXIT_ERROR


def test_fail_on_threshold_triggers_exit_1(monkeypatch):
    findings = [Finding(id="x", severity="medium", category="headers", message="m")]
    monkeypatch.setattr(cli, "run_audit", lambda *a, **k: make_result(findings))
    code = cli.main(["scan", "https://example.com", "--fail-on", "medium"])
    assert code == cli.EXIT_FINDINGS


def test_fail_on_threshold_not_triggered_below_severity(monkeypatch):
    findings = [Finding(id="x", severity="low", category="headers", message="m")]
    monkeypatch.setattr(cli, "run_audit", lambda *a, **k: make_result(findings))
    code = cli.main(["scan", "https://example.com", "--fail-on", "high"])
    assert code == cli.EXIT_CLEAN


def test_json_output_written_to_file(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "run_audit", lambda *a, **k: make_result())
    out_path = tmp_path / "report.json"
    code = cli.main(["scan", "https://example.com", "--json", str(out_path)])
    assert code == cli.EXIT_CLEAN
    data = json.loads(out_path.read_text())
    assert data["grade"] == "A"


def test_markdown_output_written_to_file(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "run_audit", lambda *a, **k: make_result())
    out_path = tmp_path / "report.md"
    code = cli.main(["scan", "https://example.com", "--markdown", str(out_path)])
    assert code == cli.EXIT_CLEAN
    assert "Grade:** A" in out_path.read_text()


def test_invalid_url_reports_error(monkeypatch, capsys):
    def raise_value_error(*a, **k):
        raise ValueError("bad scheme")

    monkeypatch.setattr(cli, "run_audit", raise_value_error)
    code = cli.main(["scan", "ftp://example.com"])
    assert code == cli.EXIT_ERROR
    assert "bad scheme" in capsys.readouterr().err


def test_missing_command_prints_help(capsys):
    with pytest.raises(SystemExit):
        cli.main([])
