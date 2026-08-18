from pathlib import Path

from codesec import secrets_scanner


def test_detects_aws_access_key():
    findings = secrets_scanner.scan_text('key = "AKIAIOSFODNN7EXAMPLE"', "f.py")
    assert any(f.rule_id == "secret-aws-access-key" for f in findings)


def test_detects_github_token():
    token = "ghp_" + "a" * 36
    findings = secrets_scanner.scan_text(f'GITHUB_TOKEN = "{token}"', "f.py")
    assert any(f.rule_id == "secret-github-token" for f in findings)


def test_detects_private_key_header():
    findings = secrets_scanner.scan_text("-----BEGIN RSA PRIVATE KEY-----", "id_rsa")
    assert any(f.rule_id == "secret-private-key" for f in findings)


def test_detects_generic_hardcoded_password():
    findings = secrets_scanner.scan_text('password = "hunter2isnotsecure"', "f.py")
    assert any(f.rule_id == "secret-generic-assignment" for f in findings)


def test_detects_prefixed_variable_name_like_db_password():
    # Regression: a leading \b before "password" fails to match inside
    # db_password because '_' is a \w character, suppressing the boundary.
    findings = secrets_scanner.scan_text('db_password = "SuperSecretPassword123!"', "f.py")
    assert any(f.rule_id == "secret-generic-assignment" for f in findings)


def test_ignores_short_password_value():
    findings = secrets_scanner.scan_text('password = "abc"', "f.py")
    assert not any(f.rule_id == "secret-generic-assignment" for f in findings)


def test_skips_commented_lines():
    findings = secrets_scanner.scan_text('# password = "hunter2isnotsecure"', "f.py")
    assert findings == []


def test_snippet_redacts_the_secret_value():
    findings = secrets_scanner.scan_text('password = "hunter2isnotsecure"', "f.py")
    assert findings
    assert "hunter2isnotsecure" not in findings[0].snippet
    assert "*" in findings[0].snippet


def test_clean_line_produces_no_findings():
    findings = secrets_scanner.scan_text('name = "vedant"', "f.py")
    assert findings == []


def test_high_entropy_generic_token_flagged_without_known_format():
    findings = secrets_scanner.scan_text(
        'X_CUSTOM_TOKEN = "qP9zK2mLwR8vB4nT6xY1cJ5aZ3"', "f.py"
    )
    assert any(f.rule_id == "secret-high-entropy-string" for f in findings)


def test_scan_path_walks_directory_and_skips_binary_dirs(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text('password = "hunter2isnotsecure"')
    (tmp_path / "app.py").write_text('password = "hunter2isnotsecure"')

    findings = secrets_scanner.scan_path(tmp_path)
    files = {f.file for f in findings}
    assert any("app.py" in f for f in files)
    assert not any(".git" in f for f in files)


def test_iter_scannable_files_single_file(tmp_path):
    target = tmp_path / "app.py"
    target.write_text("x = 1")
    files = list(secrets_scanner.iter_scannable_files(target))
    assert files == [target]


def test_iter_scannable_files_filters_by_extension(tmp_path):
    (tmp_path / "app.py").write_text("x = 1")
    (tmp_path / "image.png").write_bytes(b"\x89PNG")
    files = {p.name for p in secrets_scanner.iter_scannable_files(tmp_path)}
    assert "app.py" in files
    assert "image.png" not in files
