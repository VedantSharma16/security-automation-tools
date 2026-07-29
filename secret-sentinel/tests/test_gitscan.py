import subprocess
from pathlib import Path

import pytest

from secret_sentinel.gitscan import GitScanError, parse_git_log, scan_git_history
from secret_sentinel.patterns import load_signatures
from secret_sentinel.scanner import scan_path

DEFAULT_PATTERNS_PATH = Path(__file__).resolve().parent.parent / "rules" / "default_patterns.yaml"
SIGNATURES = load_signatures(DEFAULT_PATTERNS_PATH)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


@pytest.fixture
def git_repo_with_removed_secret(tmp_path):
    """A repo where a secret was committed, then removed in a later commit."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")

    config_file = repo / "settings.py"
    config_file.write_text('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n')
    _git(repo, "add", "settings.py")
    _git(repo, "commit", "-q", "-m", "add config with a secret")

    config_file.write_text('AWS_ACCESS_KEY_ID = "REDACTED_ROTATED_KEY"\n')
    _git(repo, "add", "settings.py")
    _git(repo, "commit", "-q", "-m", "rotate the key")

    return repo


def test_scan_git_history_finds_secret_removed_from_working_tree(git_repo_with_removed_secret):
    findings = scan_git_history(git_repo_with_removed_secret, SIGNATURES)
    aws_findings = [f for f in findings if f.signature_id == "aws-access-key-id"]
    assert len(aws_findings) == 1
    assert aws_findings[0].commit  # tagged with the commit it was added in


def test_working_tree_scan_no_longer_finds_removed_secret(git_repo_with_removed_secret):
    findings = scan_path(git_repo_with_removed_secret, SIGNATURES)
    assert not any(f.signature_id == "aws-access-key-id" for f in findings)


def test_scan_git_history_max_commits_limits_scan(git_repo_with_removed_secret):
    # Only the most recent commit (the rotation) is scanned -- the original
    # secret-adding commit is out of range, so it shouldn't be found.
    findings = scan_git_history(git_repo_with_removed_secret, SIGNATURES, max_commits=1)
    assert not any(f.signature_id == "aws-access-key-id" for f in findings)


def test_scan_git_history_raises_on_non_git_directory(tmp_path):
    not_a_repo = tmp_path / "plain_dir"
    not_a_repo.mkdir()
    with pytest.raises(GitScanError):
        scan_git_history(not_a_repo, SIGNATURES)


def test_parse_git_log_tracks_hunk_line_numbers():
    log_text = (
        "commit abc123\n"
        "Author: Test User <test@example.com>\n"
        "Date:   Mon Jan 1 00:00:00 2026 +0000\n"
        "\n"
        "    add secret\n"
        "\n"
        "diff --git a/config.py b/config.py\n"
        "new file mode 100644\n"
        "index 0000000..1111111\n"
        "--- /dev/null\n"
        "+++ b/config.py\n"
        "@@ -0,0 +1,2 @@\n"
        '+FIRST = "one"\n'
        '+SECOND = "two"\n'
    )
    added = parse_git_log(log_text)
    assert [(a.file, a.line_number, a.text) for a in added] == [
        ("config.py", 1, 'FIRST = "one"'),
        ("config.py", 2, 'SECOND = "two"'),
    ]
    assert added[0].commit == "abc123"


def test_parse_git_log_ignores_removed_lines():
    log_text = (
        "commit abc123\n"
        "Author: Test User <test@example.com>\n"
        "Date:   Mon Jan 1 00:00:00 2026 +0000\n"
        "diff --git a/config.py b/config.py\n"
        "--- a/config.py\n"
        "+++ b/config.py\n"
        "@@ -1,2 +1,1 @@\n"
        '-REMOVED = "gone"\n'
        '+KEPT = "still here"\n'
    )
    added = parse_git_log(log_text)
    assert len(added) == 1
    assert added[0].text == 'KEPT = "still here"'
