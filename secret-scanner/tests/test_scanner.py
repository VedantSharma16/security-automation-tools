import subprocess

import secret_fixtures as fx
from secret_scanner.allowlist import Allowlist
from secret_scanner.entropy import EntropyConfig
from secret_scanner.scanner import (
    is_probably_binary,
    scan_line,
    scan_text,
    scan_working_tree,
)


def test_scan_line_flags_a_signature_match():
    line = f"aws_secret_access_key = \"{fx.fake_aws_secret_access_key()}\""
    findings = scan_line(line, file_path="settings.py", line_number=3, allowlist=Allowlist(), entropy_config=None)
    assert len(findings) == 1
    assert findings[0].rule_id == "aws-secret-access-key"
    assert findings[0].line_number == 3
    assert findings[0].file_path == "settings.py"


def test_scan_line_redacts_the_value():
    secret = fx.fake_generic_api_key()
    line = f'api_key = "{secret}"'
    findings = scan_line(line, file_path="x.py", line_number=1, allowlist=Allowlist(), entropy_config=None)
    assert findings
    assert secret not in findings[0].redacted_value


def test_scan_line_suppressed_by_inline_marker():
    line = f'api_key = "{fx.fake_generic_api_key()}"  # secret-scanner:ignore'
    findings = scan_line(line, file_path="x.py", line_number=1, allowlist=Allowlist(), entropy_config=None)
    assert findings == []


def test_scan_line_suppresses_known_placeholder():
    # AWS's own published example access key ID -- a documented non-secret.
    line = 'aws_key = "AKIAIOSFODNN7EXAMPLE"'
    findings = scan_line(line, file_path="x.py", line_number=1, allowlist=Allowlist(), entropy_config=None)
    assert findings == []


def test_scan_line_entropy_and_signature_do_not_double_report_same_span():
    line = f"token = '{fx.fake_github_token()}'"
    findings = scan_line(
        line, file_path="x.py", line_number=1, allowlist=Allowlist(), entropy_config=EntropyConfig()
    )
    assert len(findings) == 1
    assert findings[0].category == "signature"


def test_scan_line_entropy_catches_unknown_format_secret():
    token = fx.random_high_entropy_token(num_bytes=32)
    line = f"session_token = '{token}'"
    findings = scan_line(
        line, file_path="x.py", line_number=1, allowlist=Allowlist(), entropy_config=EntropyConfig()
    )
    assert any(f.category == "entropy" for f in findings)


def test_scan_text_reports_correct_line_numbers():
    text = "\n".join(
        [
            "line one is clean",
            "line two is also clean",
            f'password = "{fx.fake_generic_password()}"',
        ]
    )
    findings = scan_text(text, file_path="x.py", allowlist=Allowlist(), entropy_config=None)
    assert len(findings) == 1
    assert findings[0].line_number == 3


def test_is_probably_binary_detects_null_bytes(tmp_path):
    binary_file = tmp_path / "blob.bin"
    binary_file.write_bytes(b"\x00\x01\x02binarydata")
    text_file = tmp_path / "code.py"
    text_file.write_text("print('hello')")
    assert is_probably_binary(binary_file)
    assert not is_probably_binary(text_file)


def _init_repo(root):
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)


def test_scan_working_tree_finds_secret_in_tracked_file(tmp_path):
    _init_repo(tmp_path)
    secret_file = tmp_path / "config.py"
    secret_file.write_text(f'api_key = "{fx.fake_generic_api_key()}"\n')
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)

    findings = scan_working_tree(tmp_path)
    assert len(findings) == 1
    assert findings[0].file_path == "config.py"


def test_scan_working_tree_skips_gitignored_files(tmp_path):
    _init_repo(tmp_path)
    (tmp_path / ".gitignore").write_text("ignored.py\n")
    (tmp_path / "ignored.py").write_text(f'api_key = "{fx.fake_generic_api_key()}"\n')
    (tmp_path / "tracked.py").write_text("print('clean')\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)

    findings = scan_working_tree(tmp_path)
    assert findings == []


def test_scan_working_tree_falls_back_to_walk_outside_git_repo(tmp_path):
    (tmp_path / "config.py").write_text(f'api_key = "{fx.fake_generic_api_key()}"\n')

    findings = scan_working_tree(tmp_path)
    assert len(findings) == 1


def test_scan_working_tree_respects_custom_allowlist(tmp_path):
    _init_repo(tmp_path)
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "sample.py").write_text(f'api_key = "{fx.fake_generic_api_key()}"\n')
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)

    allowlist = Allowlist(ignored_path_globs=("fixtures/*",))
    findings = scan_working_tree(tmp_path, allowlist=allowlist)
    assert findings == []


def test_scan_working_tree_clean_repo_has_no_findings(tmp_path):
    _init_repo(tmp_path)
    (tmp_path / "app.py").write_text("def main():\n    print('hello world')\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)

    assert scan_working_tree(tmp_path) == []
