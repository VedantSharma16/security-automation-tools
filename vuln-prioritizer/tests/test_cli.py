import json
from pathlib import Path

import pytest

from vuln_prioritizer.cli import main

FIXTURES = Path(__file__).resolve().parent.parent / "examples"


def test_scan_markdown_to_stdout(capsys):
    rc = main(["scan", str(FIXTURES / "sample_scan.csv"), "--assets", str(FIXTURES / "sample_assets.json")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Vulnerability Remediation Priority Report" in out
    assert "## Executive Narrative" in out  # narrator always runs, even offline


def test_scan_json_output(capsys):
    rc = main(
        [
            "scan",
            str(FIXTURES / "sample_scan.csv"),
            "--assets",
            str(FIXTURES / "sample_assets.json"),
            "--format",
            "json",
        ]
    )
    assert rc == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["summary"]["total_findings"] == 8


def test_scan_without_assets_flag_still_works(capsys):
    rc = main(["scan", str(FIXTURES / "sample_scan.csv")])
    assert rc == 0


def test_scan_writes_to_out_file(tmp_path):
    out_file = tmp_path / "report.md"
    rc = main(
        [
            "scan",
            str(FIXTURES / "sample_scan.csv"),
            "--assets",
            str(FIXTURES / "sample_assets.json"),
            "--out",
            str(out_file),
        ]
    )
    assert rc == 0
    assert out_file.exists()
    assert "Vulnerability Remediation" in out_file.read_text(encoding="utf-8")


def test_scan_missing_file_returns_error(capsys):
    rc = main(["scan", "does/not/exist.csv"])
    assert rc == 1
    assert "error" in capsys.readouterr().err


def test_scan_missing_assets_file_returns_error(capsys):
    rc = main(["scan", str(FIXTURES / "sample_scan.csv"), "--assets", "does/not/exist.json"])
    assert rc == 1
    assert "error" in capsys.readouterr().err


def test_scan_respects_top_flag(capsys):
    rc = main(
        [
            "scan",
            str(FIXTURES / "sample_scan.csv"),
            "--assets",
            str(FIXTURES / "sample_assets.json"),
            "--top",
            "2",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert out.count("### [") == 2


def test_no_command_prints_help():
    with pytest.raises(SystemExit):
        main([])
