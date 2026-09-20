import json
import subprocess
from pathlib import Path

import pytest

from secret_fixtures import build_dirty_file_text, fake_aws_access_key_id
from secret_scanner import cli

FIXTURES = Path(__file__).parent / "fixtures"


def _run_git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


@pytest.fixture
def clean_dir(tmp_path):
    (tmp_path / "clean.py").write_text((FIXTURES / "clean_file.py").read_text())
    return tmp_path


@pytest.fixture
def dirty_dir(tmp_path):
    (tmp_path / "secrets.py").write_text(build_dirty_file_text())
    return tmp_path


class TestScanCommand:
    def test_clean_scan_exits_zero_and_reports_no_secrets(self, clean_dir, capsys):
        exit_code = cli.run(["scan", str(clean_dir)])
        assert exit_code == 0
        assert "No secrets found" in capsys.readouterr().out

    def test_dirty_scan_exits_nonzero_by_default(self, dirty_dir, capsys):
        exit_code = cli.run(["scan", str(dirty_dir)])
        out = capsys.readouterr().out
        assert exit_code == 1
        assert "aws-access-key-id" in out

    def test_fail_on_none_always_exits_zero(self, dirty_dir):
        assert cli.run(["scan", str(dirty_dir), "--fail-on", "none"]) == 0

    def test_json_format_is_valid_json(self, dirty_dir, capsys):
        cli.run(["scan", str(dirty_dir), "--format", "json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["summary"]["critical"] >= 1

    def test_output_flag_writes_to_file(self, dirty_dir, tmp_path):
        out_file = tmp_path / "report.json"
        cli.run(["scan", str(dirty_dir), "--format", "json", "-o", str(out_file)])
        payload = json.loads(out_file.read_text())
        assert len(payload["findings"]) > 0

    def test_exclude_dir_skips_matching_directory(self, tmp_path, capsys):
        vendored = tmp_path / "thirdparty"
        vendored.mkdir()
        (vendored / "secrets.py").write_text(build_dirty_file_text())

        exit_code = cli.run(["scan", str(tmp_path), "--exclude-dir", "thirdparty"])
        assert exit_code == 0
        assert "No secrets found" in capsys.readouterr().out


class TestBaseline:
    def test_create_baseline_writes_file_and_exits_zero(self, dirty_dir, tmp_path):
        baseline_path = tmp_path / "baseline.json"
        exit_code = cli.run(["scan", str(dirty_dir), "--create-baseline", str(baseline_path)])
        assert exit_code == 0
        data = json.loads(baseline_path.read_text())
        assert len(data["entries"]) > 0

    def test_baseline_suppresses_previously_accepted_findings(self, dirty_dir, tmp_path, capsys):
        baseline_path = tmp_path / "baseline.json"
        cli.run(["scan", str(dirty_dir), "--create-baseline", str(baseline_path)])

        exit_code = cli.run(["scan", str(dirty_dir), "--baseline", str(baseline_path)])
        capsys.readouterr()  # discard create-baseline stderr noise from prior call
        assert exit_code == 0

        exit_code2 = cli.run(["scan", str(dirty_dir), "--baseline", str(baseline_path)])
        out = capsys.readouterr().out
        assert exit_code2 == 0
        assert "No secrets found" in out


class TestHistoryCommand:
    def test_history_scan_finds_removed_secret(self, tmp_path, capsys):
        repo = tmp_path / "repo"
        repo.mkdir()
        _run_git(repo, "init", "-q")
        _run_git(repo, "config", "user.email", "test@example.com")
        _run_git(repo, "config", "user.name", "Test User")

        secret_file = repo / "config.py"
        secret_file.write_text(f'AWS_ACCESS_KEY_ID = "{fake_aws_access_key_id()}"\n')
        _run_git(repo, "add", "config.py")
        _run_git(repo, "commit", "-q", "-m", "add secret")
        secret_file.write_text("AWS_ACCESS_KEY_ID = load_from_env()\n")
        _run_git(repo, "add", "config.py")
        _run_git(repo, "commit", "-q", "-m", "remove secret")

        exit_code = cli.run(["history", str(repo)])
        out = capsys.readouterr().out
        assert exit_code == 1
        assert "aws-access-key-id" in out


class TestArgumentParsing:
    def test_missing_command_exits_with_usage_error(self):
        with pytest.raises(SystemExit) as excinfo:
            cli.run([])
        assert excinfo.value.code != 0
