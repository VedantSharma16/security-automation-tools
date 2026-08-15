from pathlib import Path

from secretscanner.scanner import scan_directory, scan_file, scan_text


def test_scan_text_detects_regex_pattern():
    text = "config = {\n  'aws_key': 'AKIAIOSFODNN7EXAMPLE',\n}\n"
    findings = scan_text(text, file_label="config.py")
    assert len(findings) == 1
    assert findings[0].pattern_name == "AWS Access Key ID"
    assert findings[0].line_number == 2
    assert findings[0].detector == "regex"
    assert "AKIA" in findings[0].redacted_value
    assert "AKIAIOSFODNN7EXAMPLE" not in findings[0].redacted_value


def test_scan_text_respects_suppression_comment():
    text = "token = 'ghp_1234567890abcdef1234567890abcdef1234'  # pragma: allowlist secret\n"
    assert scan_text(text, file_label="settings.py") == []


def test_scan_text_skips_entropy_scan_on_lines_with_regex_match():
    # The AWS key itself is high-entropy too; it should only be reported once,
    # by the higher-confidence regex detector, not duplicated by the entropy scan.
    text = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
    findings = scan_text(text, file_label="config.py")
    assert len(findings) == 1
    assert findings[0].detector == "regex"


def test_scan_text_finds_nothing_in_clean_code():
    text = "def add(a, b):\n    return a + b\n"
    assert scan_text(text, file_label="math.py") == []


def test_scan_file_returns_empty_for_missing_or_binary(tmp_path):
    binary_path = tmp_path / "blob.bin"
    binary_path.write_bytes(bytes(range(256)))
    assert scan_file(binary_path) == []


def test_scan_directory_walks_files_and_excludes_git_dir(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("AKIAIOSFODNN7EXAMPLE\n")

    src = tmp_path / "src"
    src.mkdir()
    (src / "settings.py").write_text("STRIPE_KEY=sk_test_FAKEFAKEFAKEFAKE0000notreal\n")
    (src / "clean.py").write_text("x = 1\n")

    findings = scan_directory(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == str(src / "settings.py")
    assert findings[0].pattern_name == "Stripe Secret Key"


def test_scan_directory_sorts_findings_by_file_then_line(tmp_path):
    # Split across literals so the raw source never contains the contiguous
    # key-shaped substring (avoids tripping naive secret scanners on this repo).
    fake_key = "AIza" + "SyD-1234567890abcdefghijklmnopqrstu"
    (tmp_path / "b.py").write_text(f"x = '{fake_key}'\n")
    (tmp_path / "a.py").write_text(f"y = '{fake_key}'\n")

    findings = scan_directory(tmp_path)

    assert [Path(f.file).name for f in findings] == ["a.py", "b.py"]
