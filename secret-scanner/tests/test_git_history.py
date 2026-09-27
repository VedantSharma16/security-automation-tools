import subprocess

import secret_fixtures as fx
from secret_scanner.allowlist import Allowlist
from secret_scanner.git_history import is_git_repo, list_commits, scan_git_history
from secret_scanner.scanner import scan_working_tree


def _run(args, cwd):
    subprocess.run(args, cwd=cwd, check=True, capture_output=True)


def _init_repo(root):
    _run(["git", "init", "-q"], root)
    _run(["git", "config", "user.email", "test@example.com"], root)
    _run(["git", "config", "user.name", "Test"], root)


def test_is_git_repo_true_for_initialized_repo(tmp_path):
    _init_repo(tmp_path)
    assert is_git_repo(tmp_path)


def test_is_git_repo_false_for_plain_directory(tmp_path):
    assert not is_git_repo(tmp_path)


def test_list_commits_returns_metadata(tmp_path):
    _init_repo(tmp_path)
    (tmp_path / "a.txt").write_text("hello\n")
    _run(["git", "add", "."], tmp_path)
    _run(["git", "commit", "-q", "-m", "initial commit"], tmp_path)

    commits = list_commits(tmp_path)
    assert len(commits) == 1
    assert commits[0].subject == "initial commit"
    assert commits[0].author == "Test"


def test_scan_git_history_finds_secret_removed_in_a_later_commit(tmp_path):
    """The core scenario a working-tree-only scanner misses: a secret was
    committed, then deleted in a follow-up commit, but it's still reachable
    in the object history."""
    _init_repo(tmp_path)
    secret = fx.fake_generic_api_key()

    config = tmp_path / "config.py"
    config.write_text(f'api_key = "{secret}"\n')
    _run(["git", "add", "."], tmp_path)
    _run(["git", "commit", "-q", "-m", "add config with key"], tmp_path)

    config.write_text("api_key = os.environ['API_KEY']\n")
    _run(["git", "add", "."], tmp_path)
    _run(["git", "commit", "-q", "-m", "move key to env var"], tmp_path)

    # The current working tree is clean...
    assert scan_working_tree(tmp_path) == []

    # ...but the secret is still recoverable from history.
    history_findings = scan_git_history(tmp_path)
    assert len(history_findings) == 1
    assert history_findings[0].source == "git_history"
    assert history_findings[0].commit_subject == "add config with key"
    assert history_findings[0].commit_hash


def test_scan_git_history_respects_since(tmp_path):
    _init_repo(tmp_path)
    secret = fx.fake_generic_api_key()

    (tmp_path / "a.txt").write_text("one\n")
    _run(["git", "add", "."], tmp_path)
    _run(["git", "commit", "-q", "-m", "commit one"], tmp_path)
    first_commit = list_commits(tmp_path)[0].commit_hash

    (tmp_path / "config.py").write_text(f'api_key = "{secret}"\n')
    _run(["git", "add", "."], tmp_path)
    _run(["git", "commit", "-q", "-m", "commit two, adds secret"], tmp_path)

    assert len(scan_git_history(tmp_path, since=first_commit)) == 1
    # Scanning from HEAD (nothing new since) should find nothing.
    head = list_commits(tmp_path)[0].commit_hash
    assert scan_git_history(tmp_path, since=head) == []


def test_scan_git_history_respects_allowlist(tmp_path):
    _init_repo(tmp_path)
    secret = fx.fake_generic_api_key()
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "sample.py").write_text(f'api_key = "{secret}"\n')
    _run(["git", "add", "."], tmp_path)
    _run(["git", "commit", "-q", "-m", "add fixture"], tmp_path)

    allowlist = Allowlist(ignored_path_globs=("fixtures/*",))
    assert scan_git_history(tmp_path, allowlist=allowlist) == []


def test_scan_git_history_on_non_repo_returns_empty(tmp_path):
    (tmp_path / "config.py").write_text(f'api_key = "{fx.fake_generic_api_key()}"\n')
    assert scan_git_history(tmp_path) == []
