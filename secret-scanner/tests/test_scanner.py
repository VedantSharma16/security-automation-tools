from secretscan.scanner import (
    discover_files,
    fingerprint,
    redact,
    scan_file,
    scan_working_tree,
)


def test_redact_short_value():
    assert redact("ab") == "…"
    assert redact("abcd1234") == "ab…"


def test_redact_long_value_keeps_prefix_and_suffix_only():
    result = redact("AKIAIOSFODNN7EXAMPLE")
    assert result == "AKIA…MPLE"
    assert "IOSFODNN7EXA" not in result


def test_fingerprint_is_stable_and_scoped_to_rule_file_and_value():
    a = fingerprint("aws-access-key-id", "config.py", "AKIAIOSFODNN7EXAMPLE")
    b = fingerprint("aws-access-key-id", "config.py", "AKIAIOSFODNN7EXAMPLE")
    c = fingerprint("aws-access-key-id", "other.py", "AKIAIOSFODNN7EXAMPLE")
    assert a == b
    assert a != c


def test_discover_files_skips_vendor_dirs_and_binaries(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')\n")
    vendor = tmp_path / "node_modules"
    vendor.mkdir()
    (vendor / "lib.js").write_text("console.log('noop')")
    gitdir = tmp_path / ".git"
    gitdir.mkdir()
    (gitdir / "config").write_text("[core]")
    (tmp_path / "image.bin").write_bytes(b"\x89PNG\x00\x01\x02binarydata")

    found = {str(p) for p in discover_files(str(tmp_path))}
    assert str(tmp_path / "app.py") in found
    assert not any("node_modules" in p for p in found)
    assert not any(".git" in p for p in found)
    assert not any(p.endswith("image.bin") for p in found)


def test_scan_file_finds_aws_key(tmp_path):
    target = tmp_path / "settings.py"
    target.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\nDEBUG = True\n')

    findings = scan_file(str(target), str(tmp_path))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "aws-access-key-id"
    assert finding.file == "settings.py"
    assert finding.line == 1
    assert finding.severity == "HIGH"
    assert "AKIAIOSFODNN7EXAMPLE" not in finding.redacted


def test_scan_file_ignores_clean_code(tmp_path):
    target = tmp_path / "clean.py"
    target.write_text("def add(a, b):\n    return a + b\n")

    assert scan_file(str(target), str(tmp_path)) == []


def test_scan_working_tree_aggregates_across_files(tmp_path):
    (tmp_path / "a.py").write_text('token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12"\n')
    (tmp_path / "b.py").write_text("x = 1\n")
    sub = tmp_path / "sub"
    sub.mkdir()
    # \x2d hex-escaped hyphens: see the comment atop tests/test_rules.py -
    # keeps this fake token out of raw source bytes as a scannable literal.
    (sub / "c.env").write_text('SLACK_TOKEN=xoxb\x2d1234567890\x2d1234567890123\x2dabcdefghijklmnopqrstuvwx\n')

    findings = scan_working_tree(str(tmp_path))

    rule_ids = {f.rule_id for f in findings}
    assert rule_ids == {"github-token", "slack-token"}
    files = {f.file for f in findings}
    assert "a.py" in files
    assert str((sub / "c.env").relative_to(tmp_path)) in files


def test_scan_working_tree_respects_extra_excludes(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    (scratch / "leak.py").write_text('token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12"\n')

    findings = scan_working_tree(str(tmp_path), extra_excludes={"scratch"})

    assert findings == []
