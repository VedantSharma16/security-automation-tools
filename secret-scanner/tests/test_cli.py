import json
import subprocess

from secretscan.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, main


def _git(repo_path, *args):
    subprocess.run(["git", "-C", str(repo_path), *args], check=True, capture_output=True, text=True)


def _no_allowlist_args(tmp_path):
    return ["--allowlist", str(tmp_path / "does-not-exist-allowlist")]


class TestCliExitCodes:
    def test_clean_directory_exits_clean(self, tmp_path, capsys):
        (tmp_path / "clean.py").write_text("def add(a, b):\n    return a + b\n")
        code = main([str(tmp_path), *_no_allowlist_args(tmp_path)])
        assert code == EXIT_CLEAN

    def test_directory_with_secret_exits_findings(self, tmp_path, capsys):
        (tmp_path / "config.py").write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
        code = main([str(tmp_path), *_no_allowlist_args(tmp_path)])
        assert code == EXIT_FINDINGS
        out = capsys.readouterr().out
        assert "aws-access-key-id" in out

    def test_nonexistent_path_exits_error(self, tmp_path, capsys):
        code = main([str(tmp_path / "does-not-exist")])
        assert code == EXIT_ERROR
        assert "error" in capsys.readouterr().err


class TestCliOutputFormats:
    def test_json_format_is_valid_json(self, tmp_path, capsys):
        (tmp_path / "config.py").write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
        main([str(tmp_path), "--format", "json", *_no_allowlist_args(tmp_path)])
        out = capsys.readouterr().out
        report = json.loads(out)
        assert report["finding_count"] == 1

    def test_json_out_writes_file(self, tmp_path, capsys):
        (tmp_path / "config.py").write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
        json_path = tmp_path / "report.json"
        main([str(tmp_path), "--json-out", str(json_path), *_no_allowlist_args(tmp_path)])
        report = json.loads(json_path.read_text())
        assert report["finding_count"] == 1

    def test_no_summary_omits_executive_summary_section(self, tmp_path, capsys):
        (tmp_path / "config.py").write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
        main([str(tmp_path), "--no-summary", *_no_allowlist_args(tmp_path)])
        assert "Executive Summary" not in capsys.readouterr().out

    def test_summary_included_by_default(self, tmp_path, capsys):
        (tmp_path / "config.py").write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
        main([str(tmp_path), *_no_allowlist_args(tmp_path)])
        assert "Executive Summary" in capsys.readouterr().out


class TestCliSeverityAndAllowlist:
    def test_min_severity_filters_low_findings(self, tmp_path, capsys):
        (tmp_path / "config.py").write_text(
            'aws_key = "AKIAIOSFODNN7EXAMPLE"\n'
            'internal_token = "9fA2xQ7mZ0pL5vC8rT1yW3nB6hK4eD9gU2i"\n'
        )
        code = main([str(tmp_path), "--min-severity", "critical", *_no_allowlist_args(tmp_path)])
        assert code == EXIT_FINDINGS
        out = capsys.readouterr().out
        assert "aws-access-key-id" in out
        assert "generic-high-entropy-secret" not in out

    def test_allowlist_file_suppresses_finding(self, tmp_path, capsys):
        (tmp_path / "config.py").write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
        allow_file = tmp_path / ".secretsallowlist"
        allow_file.write_text("rule:aws-access-key-id\n")
        code = main([str(tmp_path), "--allowlist", str(allow_file)])
        assert code == EXIT_CLEAN


class TestCliGitHistory:
    def test_git_history_flag_finds_removed_secret(self, tmp_path, capsys):
        repo = tmp_path / "repo"
        repo.mkdir()
        _git(repo, "init", "-q")
        _git(repo, "config", "user.email", "test@example.com")
        _git(repo, "config", "user.name", "Test User")

        config = repo / "config.py"
        config.write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
        _git(repo, "add", "config.py")
        _git(repo, "commit", "-q", "-m", "add secret")

        config.write_text('aws_key = os.environ["AWS_KEY"]\n')
        _git(repo, "add", "config.py")
        _git(repo, "commit", "-q", "-m", "remove secret")

        code = main([str(repo), "--git-history", *_no_allowlist_args(repo)])
        assert code == EXIT_FINDINGS
        out = capsys.readouterr().out
        assert "git-history" in out or "commit" in out

    def test_without_git_history_flag_misses_removed_secret(self, tmp_path, capsys):
        repo = tmp_path / "repo"
        repo.mkdir()
        _git(repo, "init", "-q")
        _git(repo, "config", "user.email", "test@example.com")
        _git(repo, "config", "user.name", "Test User")

        config = repo / "config.py"
        config.write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
        _git(repo, "add", "config.py")
        _git(repo, "commit", "-q", "-m", "add secret")

        config.write_text('aws_key = os.environ["AWS_KEY"]\n')
        _git(repo, "add", "config.py")
        _git(repo, "commit", "-q", "-m", "remove secret")

        code = main([str(repo), *_no_allowlist_args(repo)])
        assert code == EXIT_CLEAN
