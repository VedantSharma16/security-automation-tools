import json
import subprocess
from pathlib import Path

import secret_fixtures as fx
from secret_scanner.cli import EXIT_CLEAN, EXIT_FINDINGS, main


def _run(args, cwd):
    subprocess.run(args, cwd=cwd, check=True, capture_output=True)


def _init_repo(root: Path):
    _run(["git", "init", "-q"], root)
    _run(["git", "config", "user.email", "test@example.com"], root)
    _run(["git", "config", "user.name", "Test"], root)


def test_cli_exits_clean_on_repo_with_no_secrets(tmp_path, capsys):
    _init_repo(tmp_path)
    (tmp_path / "app.py").write_text("print('hello world')\n")
    _run(["git", "add", "."], tmp_path)

    exit_code = main([str(tmp_path), "--no-narrative"])
    out = capsys.readouterr().out
    assert exit_code == EXIT_CLEAN
    assert "No secrets detected." in out


def test_cli_exits_with_findings_when_secret_present(tmp_path, capsys):
    _init_repo(tmp_path)
    (tmp_path / "config.py").write_text(f'api_key = "{fx.fake_generic_api_key()}"\n')
    _run(["git", "add", "."], tmp_path)

    exit_code = main([str(tmp_path), "--no-narrative"])
    out = capsys.readouterr().out
    assert exit_code == EXIT_FINDINGS
    assert "generic-api-key-assignment" in out


def test_cli_min_severity_filters_output(tmp_path, capsys):
    _init_repo(tmp_path)
    (tmp_path / "config.py").write_text(f'password = "{fx.fake_generic_password()}"\n')
    _run(["git", "add", "."], tmp_path)

    exit_code = main([str(tmp_path), "--min-severity", "critical", "--no-narrative"])
    out = capsys.readouterr().out
    assert exit_code == EXIT_CLEAN
    assert "No secrets detected." in out


def test_cli_writes_json_report(tmp_path, capsys):
    _init_repo(tmp_path)
    (tmp_path / "config.py").write_text(f'api_key = "{fx.fake_generic_api_key()}"\n')
    _run(["git", "add", "."], tmp_path)
    json_out = tmp_path / "report.json"

    main([str(tmp_path), "--json-out", str(json_out), "--no-narrative"])
    capsys.readouterr()

    data = json.loads(json_out.read_text())
    assert data["summary"]["total_findings"] == 1


def test_cli_writes_markdown_report(tmp_path, capsys):
    _init_repo(tmp_path)
    (tmp_path / "config.py").write_text(f'api_key = "{fx.fake_generic_api_key()}"\n')
    _run(["git", "add", "."], tmp_path)
    md_out = tmp_path / "report.md"

    main([str(tmp_path), "--markdown-out", str(md_out), "--no-narrative"])
    capsys.readouterr()

    assert "Secret Scan Report" in md_out.read_text()


def test_cli_git_history_flag_finds_purged_secret(tmp_path, capsys):
    _init_repo(tmp_path)
    secret = fx.fake_generic_api_key()
    config = tmp_path / "config.py"
    config.write_text(f'api_key = "{secret}"\n')
    _run(["git", "add", "."], tmp_path)
    _run(["git", "commit", "-q", "-m", "add secret"], tmp_path)
    config.write_text("api_key = os.environ['API_KEY']\n")
    _run(["git", "add", "."], tmp_path)
    _run(["git", "commit", "-q", "-m", "remove secret"], tmp_path)

    without_history = main([str(tmp_path), "--no-narrative"])
    assert without_history == EXIT_CLEAN
    capsys.readouterr()

    with_history = main([str(tmp_path), "--git-history", "--no-narrative"])
    out = capsys.readouterr().out
    assert with_history == EXIT_FINDINGS
    assert "git history" in out.lower() or "commit" in out.lower()


def test_cli_no_entropy_flag_suppresses_entropy_findings(tmp_path, capsys):
    _init_repo(tmp_path)
    token = fx.random_high_entropy_token(num_bytes=32)
    (tmp_path / "config.py").write_text(f"session_token = '{token}'\n")
    _run(["git", "add", "."], tmp_path)

    exit_code = main([str(tmp_path), "--no-entropy", "--no-narrative"])
    out = capsys.readouterr().out
    assert exit_code == EXIT_CLEAN
    assert "No secrets detected." in out


def test_cli_ignore_file_suppresses_findings(tmp_path, capsys):
    _init_repo(tmp_path)
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "sample.py").write_text(f'api_key = "{fx.fake_generic_api_key()}"\n')
    (tmp_path / ".secretscanignore").write_text("path:fixtures/*\n")
    _run(["git", "add", "."], tmp_path)

    exit_code = main([str(tmp_path), "--no-narrative"])
    capsys.readouterr()
    assert exit_code == EXIT_CLEAN


def test_cli_prints_triage_narrative_by_default(tmp_path, capsys):
    _init_repo(tmp_path)
    (tmp_path / "config.py").write_text(f'api_key = "{fx.fake_generic_api_key()}"\n')
    _run(["git", "add", "."], tmp_path)

    main([str(tmp_path)])
    out = capsys.readouterr().out
    assert "--- Triage ---" in out
    assert "Recommended actions" in out
