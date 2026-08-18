import json

import pytest

from codesec.cli import main


def test_scan_clean_file_exits_zero(tmp_path, capsys):
    clean = tmp_path / "clean.py"
    clean.write_text("x = 1\n")

    exit_code = main(["scan", str(clean), "--format", "json"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["total_findings"] == 0


def test_scan_vulnerable_file_default_exit_code_is_zero(tmp_path, capsys):
    bad = tmp_path / "bad.py"
    bad.write_text("eval(user_input)\n")

    exit_code = main(["scan", str(bad), "--format", "json"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["total_findings"] >= 1


def test_scan_with_fail_on_gate_returns_nonzero(tmp_path, capsys):
    bad = tmp_path / "bad.py"
    bad.write_text("eval(user_input)\n")

    exit_code = main(["scan", str(bad), "--format", "json", "--fail-on", "HIGH"])

    assert exit_code == 1


def test_scan_with_fail_on_gate_below_severity_returns_zero(tmp_path, capsys):
    bad = tmp_path / "bad.py"
    bad.write_text("eval(user_input)\n")  # HIGH severity

    exit_code = main(["scan", str(bad), "--format", "json", "--fail-on", "CRITICAL"])

    assert exit_code == 0


def test_scan_missing_path_returns_error_code(capsys):
    exit_code = main(["scan", "/no/such/path/exists.py"])
    assert exit_code == 2
    assert "no such file or directory" in capsys.readouterr().err


def test_scan_writes_to_output_file(tmp_path):
    bad = tmp_path / "bad.py"
    bad.write_text("eval(user_input)\n")
    out = tmp_path / "report.json"

    exit_code = main(["scan", str(bad), "--format", "json", "--out", str(out)])

    assert exit_code == 0
    payload = json.loads(out.read_text())
    assert payload["summary"]["total_findings"] >= 1


def test_scan_skip_flags_disable_detectors(tmp_path, capsys):
    mixed = tmp_path / "mixed.py"
    mixed.write_text('password = "hardcodedvalue123"\neval(user_input)\n')

    main(["scan", str(mixed), "--format", "json", "--skip-patterns"])
    payload = json.loads(capsys.readouterr().out)
    rule_ids = {f["rule_id"] for f in payload["findings"]}
    assert "py-eval-exec" not in rule_ids
    assert "secret-generic-assignment" in rule_ids

    main(["scan", str(mixed), "--format", "json", "--skip-secrets"])
    payload = json.loads(capsys.readouterr().out)
    rule_ids = {f["rule_id"] for f in payload["findings"]}
    assert "py-eval-exec" in rule_ids
    assert "secret-generic-assignment" not in rule_ids


def test_scan_directory_counts_all_files(tmp_path, capsys):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.py").write_text("y = 2\n")

    main(["scan", str(tmp_path), "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["files_scanned"] == 2


def test_main_without_subcommand_exits_nonzero():
    # argparse enforces the required subcommand itself, via SystemExit.
    with pytest.raises(SystemExit) as exc_info:
        main([])
    assert exc_info.value.code != 0
