import subprocess

import pytest

from secretscan.git_scanner import GitScanError, parse_added_lines, scan_git_history
from secretscan.rules import load_rules


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


@pytest.fixture
def git_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    return repo


def test_parse_added_lines_tracks_file_and_line_number():
    patch = (
        "commit abc123456789\n"
        "Author: Test <test@example.com>\n"
        "Date:   Mon Jan 1 00:00:00 2024 +0000\n"
        "\n"
        "diff --git a/app.py b/app.py\n"
        "new file mode 100644\n"
        "index 0000000..e69de29\n"
        "--- /dev/null\n"
        "+++ b/app.py\n"
        "@@ -0,0 +1,2 @@\n"
        "+line one\n"
        "+line two\n"
    )
    entries = list(parse_added_lines(patch))
    assert [e["text"] for e in entries] == ["line one", "line two"]
    assert [e["line_number"] for e in entries] == [1, 2]
    assert entries[0]["file"] == "app.py"
    assert entries[0]["commit"] == "abc123456789"


def test_parse_added_lines_ignores_removed_lines():
    patch = (
        "commit abc123456789\n"
        "Author: Test <test@example.com>\n"
        "Date:   Mon Jan 1 00:00:00 2024 +0000\n"
        "diff --git a/app.py b/app.py\n"
        "index e69de29..0000000 100644\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,2 +1 @@\n"
        "-removed line\n"
        "+kept line\n"
    )
    entries = list(parse_added_lines(patch))
    assert [e["text"] for e in entries] == ["kept line"]


def test_scan_git_history_finds_secret_even_after_removal(git_repo, default_rules_path):
    rules = load_rules(default_rules_path)
    secret_file = git_repo / "config.py"

    secret_file.write_text('token = "ghp_' + "a" * 36 + '"\n')
    _git(git_repo, "add", "config.py")
    _git(git_repo, "commit", "-q", "-m", "add config with token")

    secret_file.write_text("token = None\n")
    _git(git_repo, "add", "config.py")
    _git(git_repo, "commit", "-q", "-m", "remove token")

    findings = scan_git_history(git_repo, rules, enable_entropy=False)

    assert len(findings) == 1
    assert findings[0].rule_id == "github-pat"
    assert findings[0].commit is not None


def test_scan_git_history_respects_max_commits(git_repo, default_rules_path):
    rules = load_rules(default_rules_path)

    (git_repo / "a.py").write_text('token = "ghp_' + "a" * 36 + '"\n')
    _git(git_repo, "add", "a.py")
    _git(git_repo, "commit", "-q", "-m", "commit with secret")

    (git_repo / "b.py").write_text("clean = True\n")
    _git(git_repo, "add", "b.py")
    _git(git_repo, "commit", "-q", "-m", "clean commit")

    findings = scan_git_history(git_repo, rules, enable_entropy=False, max_commits=1)
    assert findings == []


def test_scan_git_history_raises_on_non_git_directory(tmp_path, default_rules_path):
    rules = load_rules(default_rules_path)
    with pytest.raises(GitScanError):
        scan_git_history(tmp_path, rules)
