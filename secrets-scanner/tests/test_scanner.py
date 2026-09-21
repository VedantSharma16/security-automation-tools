import pytest
from conftest import commit_file

from secretscan.gitscan import GitCommandError
from secretscan.rules import load_rules
from secretscan.scanner import scan

RULES = load_rules()


def test_scan_working_tree_only_by_default(tmp_path):
    (tmp_path / "config.py").write_text("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
    findings = scan(tmp_path, RULES)
    assert len(findings) == 1
    assert findings[0].source == "working-tree"


def test_scan_include_history_adds_history_findings(git_repo):
    commit_file(git_repo, "secrets.py", "AWS_KEY = 'AKIAIOSFODNN7QRSTUVW'\n", "add key")
    commit_file(git_repo, "secrets.py", "AWS_KEY = 'removed'\n", "remove key")

    findings = scan(git_repo, RULES, include_history=True)

    sources = {f.source for f in findings}
    assert sources == {"git-history"}  # working tree is clean, only history has it


def test_scan_include_history_on_non_repo_raises(tmp_path):
    with pytest.raises(GitCommandError):
        scan(tmp_path, RULES, include_history=True)


def test_scan_applies_baseline(tmp_path):
    (tmp_path / "config.py").write_text("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
    first_pass = scan(tmp_path, RULES)
    baseline = {first_pass[0].fingerprint}

    second_pass = scan(tmp_path, RULES, baseline=baseline)
    assert second_pass == []
