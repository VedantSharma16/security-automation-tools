from secretscanner.rules import load_default_rules
from secretscanner.scanner import is_binary, iter_text_files, scan_file, scan_path
from sample_secrets import GENERIC_SECRET_VALUE, GITHUB_TOKEN, STRIPE_LIVE_SECRET_KEY


def make_rules():
    return load_default_rules()


def test_scan_path_finds_secret_in_source_file(tmp_path):
    (tmp_path / "config.py").write_text(
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
    )
    findings, files_scanned = scan_path(tmp_path, make_rules())

    assert files_scanned == 1
    assert len(findings) == 1
    assert findings[0].rule.id == "aws-access-key-id"
    assert findings[0].file == "config.py"
    assert findings[0].line_number == 1


def test_scan_path_reports_correct_line_number_for_later_lines(tmp_path):
    (tmp_path / "app.py").write_text(
        "import os\n"
        "\n"
        f'GITHUB_TOKEN = "{GITHUB_TOKEN}"\n'
    )
    findings, _ = scan_path(tmp_path, make_rules())

    assert len(findings) == 1
    assert findings[0].line_number == 3


def test_scan_path_skips_excluded_directories(tmp_path):
    vendored = tmp_path / "node_modules" / "pkg"
    vendored.mkdir(parents=True)
    (vendored / "secrets.js").write_text('const key = "AKIAIOSFODNN7EXAMPLE";\n')

    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text('key = "AKIAIOSFODNN7EXAMPLE"\n')

    findings, files_scanned = scan_path(tmp_path, make_rules())

    assert findings == []
    assert files_scanned == 0


def test_scan_path_skips_binary_files(tmp_path):
    (tmp_path / "image.bin").write_bytes(b"\x00\x01\x02AKIAIOSFODNN7EXAMPLE")

    findings, files_scanned = scan_path(tmp_path, make_rules())

    assert findings == []
    assert files_scanned == 0


def test_scan_path_honors_custom_exclude_globs(tmp_path):
    (tmp_path / "keep.py").write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    (tmp_path / "fixtures.py").write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\n')

    findings, files_scanned = scan_path(tmp_path, make_rules(), exclude_globs=("fixtures.py",))

    assert files_scanned == 1
    assert len(findings) == 1
    assert findings[0].file == "keep.py"


def test_scan_path_clean_repo_has_no_findings(tmp_path):
    (tmp_path / "app.py").write_text("def add(a, b):\n    return a + b\n")

    findings, files_scanned = scan_path(tmp_path, make_rules())

    assert files_scanned == 1
    assert findings == []


def test_finding_redacted_secret_hides_middle_characters(tmp_path):
    (tmp_path / "config.py").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    findings, _ = scan_path(tmp_path, make_rules())

    redacted = findings[0].redacted_secret()
    assert redacted.startswith("AKIA")
    assert redacted.endswith("MPLE")
    assert findings[0].secret not in redacted


def test_finding_fingerprint_is_stable_across_runs(tmp_path):
    (tmp_path / "config.py").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    findings_a, _ = scan_path(tmp_path, make_rules())
    findings_b, _ = scan_path(tmp_path, make_rules())

    assert findings_a[0].fingerprint() == findings_b[0].fingerprint()


def test_is_binary_true_for_null_byte_content(tmp_path):
    path = tmp_path / "blob.dat"
    path.write_bytes(b"\x00abc")
    assert is_binary(path)


def test_is_binary_false_for_text_content(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("just some text")
    assert not is_binary(path)


def test_iter_text_files_skips_oversized_files(tmp_path):
    small = tmp_path / "small.txt"
    small.write_text("hello")
    large = tmp_path / "large.txt"
    large.write_text("x" * 100)

    found = list(iter_text_files(tmp_path, max_file_size=50))
    assert small in found
    assert large not in found


def test_scan_file_returns_empty_list_for_missing_file(tmp_path):
    missing = tmp_path / "does_not_exist.py"
    assert scan_file(missing, tmp_path, make_rules()) == []


def test_scan_path_dedupes_generic_match_against_specific_signature_on_same_line(tmp_path):
    # "STRIPE_SECRET_KEY = ..." trips both the Stripe-specific rule and the
    # generic "*_secret_key = <high-entropy>" rule for the same value; only
    # the more specific signature should be reported.
    (tmp_path / "config.py").write_text(
        f'STRIPE_SECRET_KEY = "{STRIPE_LIVE_SECRET_KEY}"\n'
    )
    findings, _ = scan_path(tmp_path, make_rules())

    assert len(findings) == 1
    assert findings[0].rule.id == "stripe-live-secret-key"


def test_scan_path_keeps_generic_match_with_no_competing_signature(tmp_path):
    (tmp_path / "config.py").write_text(f'client_secret = "{GENERIC_SECRET_VALUE}"\n')
    findings, _ = scan_path(tmp_path, make_rules())

    assert len(findings) == 1
    assert findings[0].rule.id == "generic-secret-assignment"
