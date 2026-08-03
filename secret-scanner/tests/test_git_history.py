import subprocess

import pytest

from secretscan.git_history import GitError, scan_git_history


def _git(repo_path, *args):
    subprocess.run(["git", "-C", str(repo_path), *args], check=True, capture_output=True, text=True)


@pytest.fixture
def repo(tmp_path):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    _git(repo_path, "init", "-q")
    _git(repo_path, "config", "user.email", "test@example.com")
    _git(repo_path, "config", "user.name", "Test User")
    return repo_path


class TestScanGitHistory:
    def test_raises_on_non_repo(self, tmp_path):
        with pytest.raises(GitError):
            scan_git_history(tmp_path)

    def test_finds_secret_committed_and_later_removed(self, repo):
        config = repo / "config.py"
        config.write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
        _git(repo, "add", "config.py")
        _git(repo, "commit", "-q", "-m", "add config with secret")

        config.write_text('aws_key = os.environ["AWS_KEY"]\n')
        _git(repo, "add", "config.py")
        _git(repo, "commit", "-q", "-m", "remove hardcoded secret")

        findings = scan_git_history(repo)
        assert len(findings) == 1
        assert findings[0].rule_id == "aws-access-key-id"
        assert findings[0].source == "git-history"
        assert findings[0].commit is not None
        assert findings[0].file == "config.py"

    def test_clean_history_yields_no_findings(self, repo):
        (repo / "readme.txt").write_text("hello world\n")
        _git(repo, "add", "readme.txt")
        _git(repo, "commit", "-q", "-m", "initial commit")

        assert scan_git_history(repo) == []

    def test_max_commits_limits_scan_depth(self, repo):
        (repo / "f1.py").write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
        _git(repo, "add", "f1.py")
        _git(repo, "commit", "-q", "-m", "commit with secret")

        (repo / "f2.py").write_text("clean = True\n")
        _git(repo, "add", "f2.py")
        _git(repo, "commit", "-q", "-m", "later clean commit")

        assert scan_git_history(repo, max_commits=1) == []
        assert len(scan_git_history(repo, max_commits=2)) == 1

    def test_allowlist_applies_to_history_findings(self, repo):
        from secretscan.allowlist import Allowlist

        (repo / "config.py").write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
        _git(repo, "add", "config.py")
        _git(repo, "commit", "-q", "-m", "add secret")

        allowlist = Allowlist(rule_ids=frozenset({"aws-access-key-id"}))
        assert scan_git_history(repo, allowlist=allowlist) == []
