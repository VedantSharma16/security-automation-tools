import json

from secretscanner.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, main
from sample_secrets import AWS_ACCESS_KEY_ID, GENERIC_SECRET_VALUE, GITHUB_TOKEN


def test_main_exits_clean_on_repo_with_no_secrets(tmp_path, capsys):
    (tmp_path / "app.py").write_text("def add(a, b):\n    return a + b\n")

    exit_code = main([str(tmp_path), "--no-color"])

    assert exit_code == EXIT_CLEAN
    assert "No secrets found" in capsys.readouterr().out


def test_main_exits_nonzero_when_secret_found(tmp_path, capsys):
    (tmp_path / "config.py").write_text(f'AWS_KEY = "{AWS_ACCESS_KEY_ID}"\n')

    exit_code = main([str(tmp_path), "--no-color"])

    assert exit_code == EXIT_FINDINGS
    assert "aws-access-key-id" in capsys.readouterr().out


def test_main_errors_on_missing_path(capsys):
    exit_code = main(["/definitely/does/not/exist", "--no-color"])

    assert exit_code == EXIT_ERROR
    assert "error" in capsys.readouterr().err


def test_main_writes_json_report(tmp_path):
    (tmp_path / "config.py").write_text(f'AWS_KEY = "{AWS_ACCESS_KEY_ID}"\n')
    json_out = tmp_path / "report.json"

    main([str(tmp_path), "--json-out", str(json_out), "--no-color"])

    assert json_out.exists()
    data = json.loads(json_out.read_text())
    assert data["finding_count"] == 1


def test_main_writes_sarif_report(tmp_path):
    (tmp_path / "config.py").write_text(f'AWS_KEY = "{AWS_ACCESS_KEY_ID}"\n')
    sarif_out = tmp_path / "report.sarif"

    main([str(tmp_path), "--sarif-out", str(sarif_out), "--no-color"])

    assert sarif_out.exists()
    data = json.loads(sarif_out.read_text())
    assert data["version"] == "2.1.0"


def test_main_fail_on_threshold_ignores_lower_severity_findings(tmp_path):
    (tmp_path / "config.py").write_text(
        f'password = "{GENERIC_SECRET_VALUE}"\n'
    )

    exit_code = main([str(tmp_path), "--fail-on", "critical", "--no-color"])

    assert exit_code == EXIT_CLEAN


def test_main_fail_on_threshold_still_fails_for_matching_severity(tmp_path):
    (tmp_path / "config.py").write_text(f'AWS_KEY = "{AWS_ACCESS_KEY_ID}"\n')

    exit_code = main([str(tmp_path), "--fail-on", "critical", "--no-color"])

    assert exit_code == EXIT_FINDINGS


def test_main_min_severity_filters_console_output_independent_of_exit_code(tmp_path, capsys):
    (tmp_path / "config.py").write_text(
        f'password = "{GENERIC_SECRET_VALUE}"\n'
    )

    exit_code = main([str(tmp_path), "--min-severity", "critical", "--no-color"])

    out = capsys.readouterr().out
    assert "No secrets found" in out
    assert exit_code == EXIT_FINDINGS


def test_main_update_baseline_then_suppresses_known_finding(tmp_path, capsys):
    (tmp_path / "config.py").write_text(f'AWS_KEY = "{AWS_ACCESS_KEY_ID}"\n')
    baseline_path = tmp_path / "baseline.json"

    exit_code = main(
        [str(tmp_path), "--baseline", str(baseline_path), "--update-baseline", "--no-color"]
    )
    assert exit_code == EXIT_FINDINGS
    assert baseline_path.exists()

    exit_code = main([str(tmp_path), "--baseline", str(baseline_path), "--no-color"])
    out = capsys.readouterr().out

    assert exit_code == EXIT_CLEAN
    assert "No secrets found" in out
    assert "Suppressed by baseline: 1" in out


def test_main_baseline_does_not_suppress_new_finding(tmp_path, capsys):
    (tmp_path / "config.py").write_text(f'AWS_KEY = "{AWS_ACCESS_KEY_ID}"\n')
    baseline_path = tmp_path / "baseline.json"
    main([str(tmp_path), "--baseline", str(baseline_path), "--update-baseline", "--no-color"])

    (tmp_path / "other.py").write_text(
        f'GITHUB_TOKEN = "{GITHUB_TOKEN}"\n'
    )
    exit_code = main([str(tmp_path), "--baseline", str(baseline_path), "--no-color"])
    out = capsys.readouterr().out

    assert exit_code == EXIT_FINDINGS
    assert "github-token" in out


def test_main_exclude_glob_skips_matching_file(tmp_path, capsys):
    (tmp_path / "keep.py").write_text(f'AWS_KEY = "{AWS_ACCESS_KEY_ID}"\n')
    (tmp_path / "fixtures.py").write_text(f'AWS_KEY = "{AWS_ACCESS_KEY_ID}"\n')

    exit_code = main([str(tmp_path), "--exclude", "fixtures.py", "--no-color"])
    out = capsys.readouterr().out

    assert exit_code == EXIT_FINDINGS
    assert out.count("aws-access-key-id") == 1


def test_main_custom_rules_file(tmp_path, capsys):
    (tmp_path / "notes.txt").write_text("totally-custom-marker-value\n")
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        "- id: custom-marker\n"
        "  pattern: 'totally-custom-marker-value'\n"
        "  severity: high\n"
        "  category: Custom\n"
    )

    exit_code = main([str(tmp_path), "--rules", str(rules_path), "--no-color"])

    assert exit_code == EXIT_FINDINGS
    assert "custom-marker" in capsys.readouterr().out
