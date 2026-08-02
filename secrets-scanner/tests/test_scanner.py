from pathlib import Path

from secretscan.rules import load_rules
from secretscan.scanner import (
    DEFAULT_EXCLUDE_DIRS,
    iter_files,
    make_fingerprint,
    redact,
    scan_file,
    scan_lines,
    scan_paths,
)


def test_redact_short_secret_fully_masked():
    assert redact("abcd") == "****"


def test_redact_long_secret_keeps_boundary_chars():
    result = redact("AKIAABCDEFGHIJKLMNOP")
    assert result.startswith("AKIA")
    assert result.endswith("MNOP")
    assert "*" in result
    assert "ABCDEFGHIJKL" not in result


def test_make_fingerprint_stable_and_specific():
    a = make_fingerprint("app.py", "aws-access-key-id", "AKIAABCDEFGHIJKLMNOP")
    b = make_fingerprint("app.py", "aws-access-key-id", "AKIAABCDEFGHIJKLMNOP")
    c = make_fingerprint("other.py", "aws-access-key-id", "AKIAABCDEFGHIJKLMNOP")
    assert a == b
    assert a != c


def test_scan_lines_finds_rule_match(default_rules_path):
    rules = load_rules(default_rules_path)
    lines = [(1, "safe line"), (2, 'aws_key = "AKIAABCDEFGHIJKLMNOP"')]
    findings = scan_lines(lines, "config.py", rules, enable_entropy=False)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "aws-access-key-id"
    assert finding.line_number == 2
    assert finding.file_path == "config.py"
    assert "AKIAABCDEFGHIJKLMNOP" not in finding.preview


def test_scan_lines_finds_entropy_match(default_rules_path):
    rules = load_rules(default_rules_path)
    line = 'internal_secret = "Tg5kP9zQ2wR7mN3xL8vB1cH6yF4d"'
    findings = scan_lines([(1, line)], "config.py", rules, enable_entropy=True)
    assert any(f.detector == "entropy" for f in findings)


def test_scan_lines_entropy_disabled(default_rules_path):
    rules = load_rules(default_rules_path)
    line = 'internal_secret = "Tg5kP9zQ2wR7mN3xL8vB1cH6yF4d"'
    findings = scan_lines([(1, line)], "config.py", rules, enable_entropy=False)
    assert findings == []


def test_scan_lines_no_findings_on_clean_code(default_rules_path):
    rules = load_rules(default_rules_path)
    lines = [(1, "def add(a, b):"), (2, "    return a + b")]
    assert scan_lines(lines, "math.py", rules) == []


def test_iter_files_skips_excluded_dirs(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print(1)\n")
    excluded = tmp_path / ".git"
    excluded.mkdir()
    (excluded / "config").write_text("git internals\n")

    found = {p.name for p in iter_files(tmp_path, DEFAULT_EXCLUDE_DIRS)}
    assert "app.py" in found
    assert "config" not in found


def test_iter_files_skips_binary_files(tmp_path):
    (tmp_path / "image.bin").write_bytes(b"\x00\x01\x02binarydata")
    (tmp_path / "app.py").write_text("print('hi')\n")

    found = {p.name for p in iter_files(tmp_path)}
    assert "app.py" in found
    assert "image.bin" not in found


def test_iter_files_skips_oversized_files(tmp_path, monkeypatch):
    big = tmp_path / "big.py"
    big.write_text("x = 1\n")
    monkeypatch.setattr("secretscan.scanner.MAX_FILE_SIZE", 1)

    found = list(iter_files(tmp_path))
    assert big not in found


def test_scan_file_uses_relative_path(default_rules_path, tmp_path):
    rules = load_rules(default_rules_path)
    sub = tmp_path / "nested"
    sub.mkdir()
    target = sub / "secrets.py"
    target.write_text('token = "ghp_' + "a" * 36 + '"\n')

    findings = scan_file(target, rules, root=tmp_path)
    assert len(findings) == 1
    assert findings[0].file_path == "nested/secrets.py"


def test_scan_paths_scans_directory_tree(default_rules_path, tmp_path):
    rules = load_rules(default_rules_path)
    (tmp_path / "a.py").write_text('token = "ghp_' + "a" * 36 + '"\n')
    (tmp_path / "b.py").write_text("clean = True\n")

    findings = scan_paths([tmp_path], rules, enable_entropy=False)
    assert len(findings) == 1
    assert findings[0].file_path == "a.py"


def test_scan_paths_accepts_a_single_file(default_rules_path, tmp_path):
    rules = load_rules(default_rules_path)
    target = tmp_path / "config.py"
    target.write_text('token = "ghp_' + "a" * 36 + '"\n')

    findings = scan_paths([target], rules, enable_entropy=False)
    assert len(findings) == 1
    assert findings[0].file_path == "config.py"
