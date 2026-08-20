import json
from pathlib import Path

import pytest

from asm.cli import main

EXAMPLES = Path(__file__).parent.parent / "examples"
DATA = Path(__file__).parent.parent / "data" / "cve_db.json"


def test_scan_writes_markdown_report_to_file(tmp_path, capsys):
    out_file = tmp_path / "report.md"
    exit_code = main([
        "scan",
        str(EXAMPLES / "sample_scan.xml"),
        "--cve-db",
        str(DATA),
        "--out",
        str(out_file),
    ])

    assert exit_code == 0
    content = out_file.read_text(encoding="utf-8")
    assert "# Attack Surface Report" in content


def test_scan_writes_json_report_to_stdout(capsys):
    exit_code = main([
        "scan",
        str(EXAMPLES / "sample_scan.xml"),
        "--cve-db",
        str(DATA),
        "--format",
        "json",
    ])

    assert exit_code == 0
    output = capsys.readouterr().out
    parsed = json.loads(output)
    assert parsed["hosts_scanned"] == 2
    assert parsed["summary"]["total_findings"] > 0


def test_scan_uses_bundled_cve_db_by_default(capsys):
    exit_code = main(["scan", str(EXAMPLES / "sample_scan.xml"), "--format", "json"])
    assert exit_code == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["summary"]["total_findings"] > 0


def test_scan_missing_file_returns_error(capsys):
    exit_code = main(["scan", "/nonexistent/scan.xml"])
    assert exit_code == 1
    assert "no such file" in capsys.readouterr().err


def test_scan_missing_cve_db_returns_error(capsys):
    exit_code = main([
        "scan",
        str(EXAMPLES / "sample_scan.xml"),
        "--cve-db",
        "/nonexistent/db.json",
    ])
    assert exit_code == 1
    assert "no such CVE database" in capsys.readouterr().err


def test_main_without_subcommand_exits_nonzero():
    with pytest.raises(SystemExit) as exc_info:
        main([])
    assert exc_info.value.code != 0
