import subprocess

import pytest

from secretscanner.gitscan import GitScanError, scan_git_history


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


@pytest.fixture
def repo_with_removed_secret(tmp_path):
    """A repo where a secret was committed, then deleted in a later commit —
    the scenario git-history scanning exists to catch."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "dev@example.com")
    _git(repo, "config", "user.name", "Dev")

    secret_file = repo / "config.py"
    secret_file.write_text("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
    _git(repo, "add", "config.py")
    _git(repo, "commit", "-q", "-m", "add config with hardcoded key")

    secret_file.write_text("AWS_KEY = os.environ['AWS_KEY']\n")
    _git(repo, "add", "config.py")
    _git(repo, "commit", "-q", "-m", "remove hardcoded key")

    return repo


def test_scan_git_history_finds_secret_removed_from_head(repo_with_removed_secret):
    findings = scan_git_history(repo_with_removed_secret)

    assert len(findings) == 1
    gf = findings[0]
    assert gf.finding.pattern_name == "AWS Access Key ID"
    assert gf.finding.file == "config.py"
    assert gf.commit and len(gf.commit) >= 7
    assert "Dev" in gf.author


def test_scan_git_history_reports_correct_line_number(tmp_path):
    repo = tmp_path / "repo2"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "dev@example.com")
    _git(repo, "config", "user.name", "Dev")

    f = repo / "settings.py"
    f.write_text("import os\nimport sys\n\nAWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
    _git(repo, "add", "settings.py")
    _git(repo, "commit", "-q", "-m", "initial")

    findings = scan_git_history(repo)
    assert len(findings) == 1
    assert findings[0].finding.line_number == 4


def test_scan_git_history_raises_on_non_git_directory(tmp_path):
    with pytest.raises(GitScanError):
        scan_git_history(tmp_path)


def test_scan_git_history_max_commits_limits_scope(tmp_path):
    repo = tmp_path / "repo3"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "dev@example.com")
    _git(repo, "config", "user.name", "Dev")

    f = repo / "a.py"
    f.write_text("x = 1\n")
    _git(repo, "add", "a.py")
    _git(repo, "commit", "-q", "-m", "commit 1 (no secret)")

    f.write_text("x = 1\nAWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
    _git(repo, "add", "a.py")
    _git(repo, "commit", "-q", "-m", "commit 2 (adds secret)")

    f.write_text("x = 1\nAWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\ny = 2\n")
    _git(repo, "add", "a.py")
    _git(repo, "commit", "-q", "-m", "commit 3 (unrelated change)")

    assert scan_git_history(repo, max_commits=1) == []
    assert len(scan_git_history(repo, max_commits=2)) == 1
