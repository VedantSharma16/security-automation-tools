import json
from pathlib import Path

import pytest

from secret_sentinel.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, main

SAMPLE_REPO = Path(__file__).resolve().parent / "fixtures" / "sample_repo"


@pytest.fixture(autouse=True)
def no_anthropic_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


def test_main_returns_findings_exit_code_on_vulnerable_directory(capsys):
    code = main([str(SAMPLE_REPO), "--no-color"])
    assert code == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "aws-access-key-id" in out


def test_main_returns_clean_exit_code_on_clean_directory(tmp_path, capsys):
    clean_dir = tmp_path / "clean"
    clean_dir.mkdir()
    (clean_dir / "main.py").write_text("print('hello world')\n")
    code = main([str(clean_dir), "--no-color"])
    assert code == EXIT_CLEAN
    assert "No secrets detected" in capsys.readouterr().out


def test_main_writes_json_report(tmp_path):
    json_path = tmp_path / "report.json"
    main([str(SAMPLE_REPO), "--no-color", "--json-out", str(json_path)])
    report = json.loads(json_path.read_text())
    assert report["finding_count"] > 0
    assert report["scan_type"] == "filesystem"


def test_main_min_severity_filters_output(capsys):
    main([str(SAMPLE_REPO), "--no-color", "--min-severity", "critical"])
    out = capsys.readouterr().out
    assert "generic-high-entropy-string" not in out


def test_main_errors_on_missing_rules_file(tmp_path, capsys):
    missing_rules = tmp_path / "does_not_exist.yaml"
    code = main([str(SAMPLE_REPO), "--rules", str(missing_rules)])
    assert code == EXIT_ERROR
    assert "error" in capsys.readouterr().err.lower()


def test_main_errors_on_non_git_directory_for_git_history(tmp_path, capsys):
    plain_dir = tmp_path / "plain"
    plain_dir.mkdir()
    code = main([str(plain_dir), "--git-history"])
    assert code == EXIT_ERROR
    assert "error" in capsys.readouterr().err.lower()


def test_main_update_allowlist_then_rescan_suppresses_known_findings(tmp_path, capsys):
    allowlist_path = tmp_path / "allowlist.json"

    code = main([str(SAMPLE_REPO), "--no-color", "--allowlist", str(allowlist_path), "--update-allowlist"])
    assert code == EXIT_FINDINGS
    assert allowlist_path.exists()

    capsys.readouterr()  # discard first run's output
    code = main([str(SAMPLE_REPO), "--no-color", "--allowlist", str(allowlist_path)])
    assert code == EXIT_CLEAN
    assert "No secrets detected" in capsys.readouterr().out


def test_build_parser_defaults():
    from secret_sentinel.cli import build_parser

    args = build_parser().parse_args([])
    assert args.path == "."
    assert args.min_severity == "low"
    assert args.git_history is None
    assert args.llm is False


def test_git_history_flag_with_explicit_commit_limit():
    from secret_sentinel.cli import build_parser

    args = build_parser().parse_args(["--git-history", "5"])
    assert args.git_history == 5
