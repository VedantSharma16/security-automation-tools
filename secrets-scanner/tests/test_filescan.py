from secretscan.filescan import iter_scannable_files, scan_working_tree
from secretscan.rules import load_rules

RULES = load_rules()


def test_scan_working_tree_finds_a_signature_secret(tmp_path):
    (tmp_path / "config.py").write_text("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
    findings = scan_working_tree(tmp_path, RULES)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "aws-access-key-id"
    assert f.file_path == "config.py"
    assert f.line == 1
    assert f.source == "working-tree"
    assert "AKIA" not in f.redacted[4:]  # only the kept prefix contains AKIA


def test_scan_working_tree_ignores_clean_files(tmp_path):
    (tmp_path / "app.py").write_text("def main():\n    return 42\n")
    assert scan_working_tree(tmp_path, RULES) == []


def test_scan_working_tree_skips_binary_files(tmp_path):
    (tmp_path / "blob.bin").write_bytes(b"AKIAIOSFODNN7EXAMPLE\x00\x01\x02")
    assert scan_working_tree(tmp_path, RULES) == []


def test_scan_working_tree_skips_ignored_directories(tmp_path):
    nested = tmp_path / "node_modules" / "pkg"
    nested.mkdir(parents=True)
    (nested / "config.py").write_text("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
    assert scan_working_tree(tmp_path, RULES) == []


def test_scan_working_tree_captures_variable_name_as_context_key(tmp_path):
    (tmp_path / "config.py").write_text("GITHUB_TOKEN = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789'\n")
    findings = scan_working_tree(tmp_path, RULES)
    assert findings[0].context_key == "GITHUB_TOKEN"


def test_iter_scannable_files_excludes_dot_git(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "COMMIT_EDITMSG").write_text("AKIAIOSFODNN7EXAMPLE\n")
    (tmp_path / "real.py").write_text("x = 1\n")
    found = {p.name for p in iter_scannable_files(tmp_path)}
    assert found == {"real.py"}
