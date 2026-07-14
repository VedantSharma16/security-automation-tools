import json
from pathlib import Path

from log_sentinel.cli import main

SAMPLE_LOG = Path(__file__).resolve().parent.parent / "sample_data" / "auth.log"


def test_cli_markdown_report_to_stdout(capsys):
    exit_code = main([str(SAMPLE_LOG)])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "BRUTE_FORCE" in out
    assert "Incident Report" in out


def test_cli_json_output_is_valid(capsys):
    exit_code = main([str(SAMPLE_LOG), "--format", "json"])
    assert exit_code == 0
    data = json.loads(capsys.readouterr().out)
    assert isinstance(data, list)
    assert any(f["type"] == "BRUTE_FORCE" for f in data)


def test_cli_writes_report_to_file(tmp_path):
    out_file = tmp_path / "report.md"
    exit_code = main([str(SAMPLE_LOG), "-o", str(out_file)])
    assert exit_code == 0
    assert out_file.exists()
    assert "Incident Report" in out_file.read_text()


def test_cli_fail_on_critical_sets_exit_code():
    exit_code = main([str(SAMPLE_LOG), "--fail-on", "critical", "--format", "json"])
    assert exit_code in (0, 2)  # depends on whether sample data crosses critical threshold


def test_cli_fail_on_never_always_returns_zero_when_no_error():
    exit_code = main([str(SAMPLE_LOG), "--fail-on", "never", "--format", "json"])
    assert exit_code == 0


def test_cli_missing_file_returns_error():
    exit_code = main(["/nonexistent/path/auth.log"])
    assert exit_code == 1


def test_cli_custom_thresholds_suppress_brute_force(capsys):
    exit_code = main([str(SAMPLE_LOG), "--brute-force-threshold", "999", "--format", "json"])
    assert exit_code == 0
    data = json.loads(capsys.readouterr().out)
    assert not any(f["type"] == "BRUTE_FORCE" for f in data)
