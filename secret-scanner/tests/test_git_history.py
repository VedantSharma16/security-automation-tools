import os
import subprocess

import pytest

from secretscan.scanner import scan_git_history, scan_working_tree

_GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "test@example.com",
}


def _git(repo, *args):
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        env=_GIT_ENV,
    )


@pytest.fixture
def leaky_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")

    secret_file = repo / "config.py"
    secret_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    _git(repo, "add", "config.py")
    _git(repo, "commit", "-q", "-m", "add config with secret")

    # The secret is later removed from the working tree - a plain file
    # scan will find nothing, but it's still sitting in history.
    secret_file.write_text('AWS_KEY = os.environ["AWS_KEY"]\n')
    _git(repo, "add", "config.py")
    _git(repo, "commit", "-q", "-m", "load secret from env instead")

    return repo


def test_working_tree_scan_misses_secret_removed_from_head(leaky_repo):
    findings = scan_working_tree(str(leaky_repo))
    assert findings == []


def test_git_history_scan_finds_secret_from_earlier_commit(leaky_repo):
    findings = scan_git_history(str(leaky_repo))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "aws-access-key-id"
    assert finding.file == "config.py"
    assert finding.commit is not None
    assert finding.line == 1


def test_git_history_scan_on_non_git_dir_returns_empty(tmp_path):
    plain = tmp_path / "not_a_repo"
    plain.mkdir()
    assert scan_git_history(str(plain)) == []


def test_git_history_scan_max_commits_limits_lookback(leaky_repo):
    # Only look at the most recent commit, which no longer introduces the
    # secret (it was added one commit earlier).
    findings = scan_git_history(str(leaky_repo), max_commits=1)
    assert findings == []
