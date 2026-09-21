import pytest
from conftest import commit_file

from secretscan.gitscan import GitCommandError, is_git_repo, scan_git_history
from secretscan.rules import load_rules

RULES = load_rules()


def test_is_git_repo_true_for_repo(git_repo):
    assert is_git_repo(git_repo) is True


def test_is_git_repo_false_for_plain_directory(tmp_path):
    assert is_git_repo(tmp_path) is False


def test_scan_git_history_raises_on_non_repo(tmp_path):
    with pytest.raises(GitCommandError):
        scan_git_history(tmp_path, RULES)


def test_scan_git_history_finds_secret_removed_in_a_later_commit(git_repo):
    commit_file(git_repo, "secrets.py", "AWS_KEY = 'AKIAIOSFODNN7QRSTUVW'\n", "add key")
    commit_file(git_repo, "secrets.py", "AWS_KEY = 'removed'\n", "remove key")

    findings = scan_git_history(git_repo, RULES)

    assert len(findings) == 1
    assert findings[0].rule_id == "aws-access-key-id"
    assert findings[0].source == "git-history"
    assert findings[0].commit is not None
    assert findings[0].file_path == "secrets.py"


def test_scan_git_history_is_empty_for_repo_with_no_secrets(git_repo):
    commit_file(git_repo, "app.py", "def main():\n    return 1\n", "init")
    assert scan_git_history(git_repo, RULES) == []


def test_scan_git_history_handles_repo_with_no_commits(git_repo):
    assert scan_git_history(git_repo, RULES) == []


def test_scan_git_history_scans_all_branches(git_repo):
    commit_file(git_repo, "app.py", "x = 1\n", "init")
    import subprocess

    subprocess.run(["git", "checkout", "-q", "-b", "feature"], cwd=git_repo, check=True)
    commit_file(git_repo, "app.py", "AWS_KEY = 'AKIAIOSFODNN7QRSTUVW'\n", "leak on branch")
    subprocess.run(["git", "checkout", "-q", "-"], cwd=git_repo, check=True)

    findings = scan_git_history(git_repo, RULES)
    assert any(f.rule_id == "aws-access-key-id" for f in findings)


def test_finding_from_history_carries_commit_metadata(git_repo):
    sha = commit_file(git_repo, "secrets.py", "AWS_KEY = 'AKIAIOSFODNN7QRSTUVW'\n", "add key")
    findings = scan_git_history(git_repo, RULES)
    assert findings[0].commit == sha[:12]
    assert findings[0].author == "Test User"
