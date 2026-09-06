import json

from codesec_agent.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, main

VULNERABLE_SNIPPET = "import os\ndef f(x):\n    os.system(x)\n"
CLEAN_SNIPPET = "def add(a, b):\n    return a + b\n"


def test_main_exits_clean_on_clean_project(tmp_path, capsys):
    (tmp_path / "safe.py").write_text(CLEAN_SNIPPET)

    exit_code = main([str(tmp_path)])

    assert exit_code == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "LLM-backed: no" in out
    assert "No findings" in out


def test_main_exits_nonzero_when_high_severity_finding_present(tmp_path, capsys):
    (tmp_path / "app.py").write_text(VULNERABLE_SNIPPET)

    exit_code = main([str(tmp_path)])

    assert exit_code == EXIT_FINDINGS
    assert "os.system() with a dynamic command" in capsys.readouterr().out


def test_main_fail_on_threshold_can_be_relaxed(tmp_path):
    (tmp_path / "app.py").write_text(VULNERABLE_SNIPPET)  # a "high" finding
    assert main([str(tmp_path), "--fail-on", "critical"]) == EXIT_CLEAN
    assert main([str(tmp_path), "--fail-on", "high"]) == EXIT_FINDINGS


def test_main_min_severity_filters_output(tmp_path, capsys):
    (tmp_path / "app.py").write_text(VULNERABLE_SNIPPET + "\nimport hashlib\nhashlib.md5(b'x')\n")

    main([str(tmp_path), "--min-severity", "high"])
    out = capsys.readouterr().out
    assert "Findings: 0 critical, 1 high, 0 medium, 0 low" in out
    assert "CWE-78" in out


def test_main_json_output_is_valid_json(tmp_path, capsys):
    (tmp_path / "app.py").write_text(VULNERABLE_SNIPPET)

    main([str(tmp_path), "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["findings"][0]["rule_id"] == "command-injection"


def test_main_writes_json_report_file(tmp_path):
    (tmp_path / "app.py").write_text(VULNERABLE_SNIPPET)
    json_out = tmp_path / "report.json"

    main([str(tmp_path), "--json-out", str(json_out)])

    assert json_out.exists()
    assert json.loads(json_out.read_text())["llm_backed"] is False


def test_main_errors_on_missing_path(capsys):
    exit_code = main(["/no/such/path/at/all"])
    assert exit_code == EXIT_ERROR
    assert "does not exist" in capsys.readouterr().err
