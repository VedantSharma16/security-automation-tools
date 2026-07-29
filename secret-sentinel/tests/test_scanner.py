from pathlib import Path

from secret_sentinel.patterns import load_signatures
from secret_sentinel.scanner import (
    compute_fingerprint,
    redact_secret,
    scan_line,
    scan_path,
    should_skip_file,
)

DEFAULT_PATTERNS_PATH = Path(__file__).resolve().parent.parent / "rules" / "default_patterns.yaml"
SAMPLE_REPO = Path(__file__).resolve().parent / "fixtures" / "sample_repo"
SIGNATURES = load_signatures(DEFAULT_PATTERNS_PATH)


def test_redact_secret_short_value_fully_masked():
    assert redact_secret("abc123") == "******"


def test_redact_secret_keeps_prefix_and_suffix():
    value = "AKIAIOSFODNN7EXAMPLE"
    redacted = redact_secret(value)
    assert redacted.startswith("AKIA")
    assert redacted.endswith("MPLE")
    assert "*" in redacted
    assert len(redacted) == len(value)


def test_compute_fingerprint_is_deterministic():
    a = compute_fingerprint("aws-access-key-id", "AKIAIOSFODNN7EXAMPLE")
    b = compute_fingerprint("aws-access-key-id", "AKIAIOSFODNN7EXAMPLE")
    assert a == b


def test_compute_fingerprint_differs_by_value():
    a = compute_fingerprint("aws-access-key-id", "AKIAIOSFODNN7EXAMPLE")
    b = compute_fingerprint("aws-access-key-id", "AKIAOTHERVALUE123456")
    assert a != b


def test_scan_line_detects_aws_access_key_id():
    hits = scan_line('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"', SIGNATURES)
    ids = {h["signature_id"] for h in hits}
    assert "aws-access-key-id" in ids
    hit = next(h for h in hits if h["signature_id"] == "aws-access-key-id")
    assert hit["severity"] == "critical"
    assert "AKIA" not in hit["redacted_value"][4:]  # only the kept prefix contains it


def test_scan_line_detects_github_token():
    hits = scan_line('token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12"', SIGNATURES)
    assert any(h["signature_id"] == "github-token" for h in hits)


def test_scan_line_detects_private_key_block():
    hits = scan_line("-----BEGIN RSA PRIVATE KEY-----", SIGNATURES)
    assert any(h["signature_id"] == "private-key-block" for h in hits)


def test_scan_line_detects_db_connection_string_creds():
    hits = scan_line(
        'DATABASE_URL = "postgres://appuser:s3cr3tPass@db.internal.example.com:5432/prod"',
        SIGNATURES,
    )
    assert any(h["signature_id"] == "database-connection-string-creds" for h in hits)


def test_scan_line_detects_generic_high_entropy_secret():
    hits = scan_line('session_token = "Xk29LpQzT8mNc4Rb"', SIGNATURES)
    assert any(h["signature_id"] == "generic-high-entropy-string" for h in hits)


def test_scan_line_ignores_placeholder_value():
    hits = scan_line('placeholder_api_key = "your-api-key-here"', SIGNATURES)
    assert hits == []


def test_scan_line_respects_inline_ignore_marker():
    hits = scan_line(
        'secret_key = "Xk29LpQzT8mNc4Rb"  # secret-sentinel:ignore', SIGNATURES
    )
    assert hits == []


def test_scan_line_no_duplicate_report_for_named_and_generic_detector():
    # aws_secret_access_key is caught by the named signature; the generic
    # entropy detector should not also report the same value a second time.
    line = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
    hits = scan_line(line, SIGNATURES)
    assert len(hits) == 1
    assert hits[0]["signature_id"] == "aws-secret-access-key"


def test_should_skip_file_ignores_lockfiles(tmp_path):
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text("{}")
    assert should_skip_file(lockfile)


def test_should_skip_file_ignores_oversized_files(tmp_path):
    big_file = tmp_path / "big.txt"
    big_file.write_text("x" * 100)
    assert should_skip_file(big_file, max_size=10)


def test_should_skip_file_allows_normal_source_file(tmp_path):
    source = tmp_path / "main.py"
    source.write_text("print('hi')")
    assert not should_skip_file(source)


def test_scan_path_over_sample_repo_finds_expected_signatures():
    findings = scan_path(SAMPLE_REPO, SIGNATURES)
    ids_by_file = {}
    for f in findings:
        ids_by_file.setdefault(Path(f.file).name, set()).add(f.signature_id)

    assert "aws-access-key-id" in ids_by_file["app_config.py"]
    assert "aws-secret-access-key" in ids_by_file["app_config.py"]
    assert "github-token" in ids_by_file["app_config.py"]
    assert "generic-password-assignment" in ids_by_file["app_config.py"]
    assert "generic-high-entropy-string" in ids_by_file["app_config.py"]
    assert "database-connection-string-creds" in ids_by_file["app_config.py"]
    assert "private-key-block" in ids_by_file["id_rsa_fake"]


def test_scan_path_ignores_node_modules():
    findings = scan_path(SAMPLE_REPO, SIGNATURES)
    assert not any("node_modules" in f.file for f in findings)


def test_scan_path_skips_inline_ignored_finding():
    findings = scan_path(SAMPLE_REPO, SIGNATURES)
    assert not any(f.redacted_value == redact_secret("Xk29LpQzT8mNc4Rc") for f in findings)


def test_scan_path_placeholder_and_short_values_not_flagged():
    findings = scan_path(SAMPLE_REPO, SIGNATURES)
    values = [f.redacted_value for f in findings]
    assert redact_secret("your-api-key-here") not in values
    assert redact_secret("abc123") not in values


def test_scan_path_clean_file_has_no_findings():
    findings = scan_path(SAMPLE_REPO, SIGNATURES)
    assert not any(Path(f.file).name == "clean_module.py" for f in findings)
