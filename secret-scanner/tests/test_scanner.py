from secretscan.allowlist import Allowlist
from secretscan.scanner import (
    is_probably_binary,
    scan_directory,
    scan_file,
    scan_text,
)


class TestScanText:
    def test_finds_known_secret_format(self):
        findings = scan_text('aws_key = "AKIAIOSFODNN7EXAMPLE"', file_label="x.py")
        assert len(findings) == 1
        assert findings[0].rule_id == "aws-access-key-id"
        assert findings[0].line_number == 1

    def test_line_numbers_are_one_indexed_and_accurate(self):
        text = "line one\nline two\napi_key = \"abcdEFGH12345678ijklMNOP\"\nline four"
        findings = scan_text(text, file_label="x.py")
        assert findings[0].line_number == 3

    def test_no_secret_yields_no_findings(self):
        assert scan_text("just some ordinary code\nx = 1 + 2", file_label="x.py") == []

    def test_redacted_secret_never_contains_the_raw_value(self):
        findings = scan_text('aws_key = "AKIAIOSFODNN7EXAMPLE"', file_label="x.py")
        assert "AKIAIOSFODNN7EXAMPLE" not in findings[0].redacted_secret

    def test_overlapping_rules_report_once_per_span(self):
        # This value is shaped like both a generic API key assignment AND,
        # by coincidence of pattern breadth, could double-match; the more
        # specific AWS rule should win and it should be reported once.
        findings = scan_text('aws_key = "AKIAIOSFODNN7EXAMPLE"', file_label="x.py")
        assert len(findings) == 1

    def test_entropy_finding_when_no_rule_matches(self):
        text = 'internal_service_token = "9fA2xQ7mZ0pL5vC8rT1yW3nB6hK4eD9gU2i"'
        findings = scan_text(text, file_label="x.py")
        assert len(findings) == 1
        assert findings[0].rule_id == "generic-high-entropy-secret"

    def test_use_entropy_false_disables_generic_heuristic(self):
        text = 'internal_service_token = "9fA2xQ7mZ0pL5vC8rT1yW3nB6hK4eD9gU2i"'
        assert scan_text(text, file_label="x.py", use_entropy=False) == []

    def test_allowlist_suppresses_matching_finding(self):
        allowlist = Allowlist(rule_ids=frozenset({"aws-access-key-id"}))
        findings = scan_text('aws_key = "AKIAIOSFODNN7EXAMPLE"', file_label="x.py", allowlist=allowlist)
        assert findings == []

    def test_very_long_line_is_skipped(self):
        text = "x = \"" + "A" * 5000 + "\""
        assert scan_text(text, file_label="x.py") == []

    def test_git_history_source_and_commit_are_carried_through(self):
        findings = scan_text(
            'aws_key = "AKIAIOSFODNN7EXAMPLE"',
            file_label="x.py",
            source="git-history",
            commit="abc123",
        )
        assert findings[0].source == "git-history"
        assert findings[0].commit == "abc123"


class TestIsProbablyBinary:
    def test_null_byte_is_binary(self):
        assert is_probably_binary(b"hello\x00world")

    def test_plain_text_is_not_binary(self):
        assert not is_probably_binary(b"hello world, this is text\n")


class TestScanFile:
    def test_scans_a_real_file(self, tmp_path):
        f = tmp_path / "config.py"
        f.write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
        findings = scan_file(f)
        assert len(findings) == 1

    def test_skips_binary_file(self, tmp_path):
        f = tmp_path / "blob.bin"
        f.write_bytes(b"\x00\x01\x02AKIAIOSFODNN7EXAMPLE\x03\x04")
        assert scan_file(f) == []


class TestScanDirectory:
    def test_finds_secrets_across_multiple_files(self, tmp_path):
        (tmp_path / "a.py").write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
        (tmp_path / "b.py").write_text('token: ghp_1234567890abcdefghijklmnopqrstuvwxyz12\n')
        findings = scan_directory(tmp_path)
        assert len(findings) == 2
        assert {f.file for f in findings} == {"a.py", "b.py"}

    def test_skips_dotgit_and_node_modules(self, tmp_path):
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "config").write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "pkg.js").write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
        assert scan_directory(tmp_path) == []

    def test_skips_files_over_size_limit(self, tmp_path, monkeypatch):
        import secretscan.scanner as scanner_mod

        monkeypatch.setattr(scanner_mod, "MAX_FILE_SIZE_BYTES", 10)
        f = tmp_path / "big.py"
        f.write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
        assert scan_directory(tmp_path) == []

    def test_reports_paths_relative_to_scan_root(self, tmp_path):
        nested = tmp_path / "sub" / "dir"
        nested.mkdir(parents=True)
        (nested / "secret.py").write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
        findings = scan_directory(tmp_path)
        assert findings[0].file == "sub/dir/secret.py"

    def test_clean_directory_yields_no_findings(self, tmp_path):
        (tmp_path / "clean.py").write_text("def add(a, b):\n    return a + b\n")
        assert scan_directory(tmp_path) == []
