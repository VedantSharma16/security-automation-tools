from pathlib import Path

from codesec import ast_scanner

FIXTURES = Path(__file__).parent / "fixtures"


def _rule_ids(findings):
    return {f.rule_id for f in findings}


def test_detects_all_expected_rules_in_vulnerable_sample():
    findings = ast_scanner.scan_file(FIXTURES / "vulnerable_sample.py")
    rule_ids = _rule_ids(findings)

    expected = {
        "py-sql-injection",
        "py-subprocess-shell-true",
        "py-yaml-unsafe-load",
        "py-insecure-deserialization",
        "py-weak-hash",
        "py-weak-randomness",
        "py-tls-verify-disabled",
        "py-eval-exec",
        "py-os-system",
    }
    assert expected <= rule_ids


def test_dynamic_shell_command_is_critical_static_is_medium():
    findings = ast_scanner.scan_file(FIXTURES / "vulnerable_sample.py")
    shell_findings = [f for f in findings if f.rule_id == "py-subprocess-shell-true"]

    # fixture has two call sites: one built from a variable, one a string literal.
    severities = sorted(f.severity.name for f in shell_findings)
    assert severities == sorted(["CRITICAL", "MEDIUM"])


def test_clean_sample_has_no_findings():
    findings = ast_scanner.scan_file(FIXTURES / "clean_sample.py")
    assert findings == []


def test_scan_source_handles_syntax_errors_gracefully():
    findings = ast_scanner.scan_source("def broken(:\n", "broken.py")
    assert findings == []


def test_sql_injection_not_flagged_for_parameterized_query():
    source = "cursor.execute('SELECT * FROM t WHERE id = ?', (value,))\n"
    findings = ast_scanner.scan_source(source, "ok.py")
    assert not any(f.rule_id == "py-sql-injection" for f in findings)


def test_sql_injection_flagged_for_percent_formatting():
    source = "cursor.execute('SELECT * FROM t WHERE id = %s' % value)\n"
    findings = ast_scanner.scan_source(source, "bad.py")
    assert any(f.rule_id == "py-sql-injection" for f in findings)


def test_weak_randomness_only_flagged_for_sensitive_variable_names():
    sensitive = ast_scanner.scan_source("api_token = random.random()\n", "a.py")
    benign = ast_scanner.scan_source("dice_roll = random.random()\n", "b.py")
    assert any(f.rule_id == "py-weak-randomness" for f in sensitive)
    assert not any(f.rule_id == "py-weak-randomness" for f in benign)


def test_debug_mode_flagged():
    findings = ast_scanner.scan_source("app.run(debug=True)\n", "app.py")
    assert any(f.rule_id == "py-debug-mode-enabled" for f in findings)


def test_scan_path_directory_skips_venv():
    findings = ast_scanner.scan_path(FIXTURES)
    # Should include findings from vulnerable_sample.py and nothing from clean_sample.py.
    files = {f.file for f in findings}
    assert any("vulnerable_sample.py" in f for f in files)
    assert not any("clean_sample.py" in f for f in files)


def test_scan_path_single_file():
    findings = ast_scanner.scan_path(FIXTURES / "clean_sample.py")
    assert findings == []


def test_scan_path_ignores_non_python_file(tmp_path):
    (tmp_path / "notes.txt").write_text("eval('1+1')")
    findings = ast_scanner.scan_path(tmp_path)
    assert findings == []
