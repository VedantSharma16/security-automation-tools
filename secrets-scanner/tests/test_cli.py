import hashlib
import json

from secretscan.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, main


def test_cli_exits_clean_on_no_findings(tmp_path, capsys):
    (tmp_path / "app.py").write_text("def main():\n    return 1\n")
    code = main(["--no-color", str(tmp_path)])
    assert code == EXIT_CLEAN
    assert "No secrets found" in capsys.readouterr().out


def test_cli_exits_with_findings_code_when_secret_present(tmp_path, capsys):
    (tmp_path / "config.py").write_text("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
    code = main(["--no-color", str(tmp_path)])
    assert code == EXIT_FINDINGS
    assert "aws-access-key-id" in capsys.readouterr().out


def test_cli_min_severity_filters_low_severity_findings(tmp_path, capsys):
    # Assembled at runtime rather than written as a literal: a contiguous
    # "sk_test_<24+ alnum chars>" string in committed source trips GitHub's
    # push protection (it flags the provider *format*, not just known real
    # keys) even though this is a fake, non-functional value.
    fake_stripe_test_key = "sk_test_" + hashlib.sha256(b"secretscan-fixture").hexdigest()[:32]
    (tmp_path / "config.py").write_text(f"STRIPE_KEY = '{fake_stripe_test_key}'\n")
    code = main(["--no-color", "--min-severity", "high", str(tmp_path)])
    assert code == EXIT_CLEAN  # stripe TEST key is "low" severity, filtered out


def test_cli_errors_on_missing_path(capsys):
    code = main(["/no/such/path/at/all"])
    assert code == EXIT_ERROR
    assert "error:" in capsys.readouterr().err


def test_cli_create_baseline_requires_baseline_flag(tmp_path, capsys):
    code = main(["--create-baseline", str(tmp_path)])
    assert code == EXIT_ERROR
    assert "--create-baseline requires --baseline" in capsys.readouterr().err


def test_cli_create_baseline_then_rescan_is_clean(tmp_path, capsys):
    (tmp_path / "config.py").write_text("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
    baseline_path = tmp_path / "baseline.json"

    code = main(
        ["--no-color", "--baseline", str(baseline_path), "--create-baseline", str(tmp_path)]
    )
    assert code == EXIT_CLEAN
    assert baseline_path.exists()

    capsys.readouterr()
    code = main(["--no-color", "--baseline", str(baseline_path), str(tmp_path)])
    assert code == EXIT_CLEAN
    assert "No secrets found" in capsys.readouterr().out


def test_cli_writes_json_and_sarif_reports(tmp_path):
    (tmp_path / "config.py").write_text("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
    json_path = tmp_path / "report.json"
    sarif_path = tmp_path / "report.sarif"

    code = main(
        [
            "--no-color",
            "--json-out", str(json_path),
            "--sarif-out", str(sarif_path),
            str(tmp_path),
        ]
    )

    assert code == EXIT_FINDINGS
    report = json.loads(json_path.read_text())
    assert report["finding_count"] == 1

    sarif = json.loads(sarif_path.read_text())
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1


def test_cli_json_report_never_contains_the_raw_secret(tmp_path):
    (tmp_path / "config.py").write_text("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
    json_path = tmp_path / "report.json"
    main(["--no-color", "--json-out", str(json_path), str(tmp_path)])

    raw = json_path.read_text()
    assert "AKIAIOSFODNN7EXAMPLE" not in raw
    assert "AKIA...MPLE" in raw
