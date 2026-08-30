import json
from pathlib import Path

from recon_agent.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, main

FIXTURE_PATH = str(Path(__file__).resolve().parent.parent / "examples" / "fixture_example.json")


def test_cli_requires_authorization_or_fixture(capsys):
    exit_code = main(["--target", "example.com"])
    assert exit_code == EXIT_ERROR
    assert "authorized" in capsys.readouterr().err


def test_cli_runs_against_fixture_without_authorization_flag(capsys):
    exit_code = main(["--target", "example.com", "--fixture", FIXTURE_PATH, "--no-color"])
    out = capsys.readouterr().out
    assert exit_code == EXIT_FINDINGS  # the bundled fixture has intentional findings
    assert "Recon Agent — example.com" in out
    assert "hdr-no-csp" in out


def test_cli_min_severity_filters_output(capsys):
    exit_code = main(
        ["--target", "example.com", "--fixture", FIXTURE_PATH, "--no-color", "--min-severity", "critical"]
    )
    out = capsys.readouterr().out
    # Only the CORS-wildcard-with-credentials finding in the fixture is critical.
    assert "hdr-cors-wildcard-with-credentials" in out
    assert "hdr-no-csp" not in out
    assert exit_code == EXIT_FINDINGS


def test_cli_writes_json_and_markdown_reports(tmp_path, capsys):
    json_out = tmp_path / "report.json"
    md_out = tmp_path / "report.md"

    main(
        [
            "--target",
            "example.com",
            "--fixture",
            FIXTURE_PATH,
            "--no-color",
            "--json-out",
            str(json_out),
            "--md-out",
            str(md_out),
        ]
    )
    capsys.readouterr()

    report = json.loads(json_out.read_text())
    assert report["host"] == "example.com"
    assert report["finding_count"] > 0
    assert "# Recon report" in md_out.read_text()


def test_cli_missing_fixture_file_is_a_clean_error(capsys):
    exit_code = main(["--target", "example.com", "--fixture", "does/not/exist.json"])
    assert exit_code == EXIT_ERROR
    assert "fixture" in capsys.readouterr().err


def test_cli_clean_scan_exits_zero(tmp_path, capsys):
    clean_fixture = tmp_path / "clean.json"
    clean_fixture.write_text(
        json.dumps(
            {
                "https": {
                    "ok": True,
                    "status_code": 200,
                    "headers": {
                        "Strict-Transport-Security": "max-age=31536000",
                        "Content-Security-Policy": "default-src 'self'",
                        "X-Content-Type-Options": "nosniff",
                        "X-Frame-Options": "DENY",
                        "Referrer-Policy": "no-referrer",
                    },
                },
                "tls": {"ok": True, "version": "TLSv1.3", "days_until_expiry": 60},
            }
        )
    )
    exit_code = main(["--target", "example.com", "--fixture", str(clean_fixture), "--no-color"])
    assert exit_code == EXIT_CLEAN
    assert "No header/TLS findings" in capsys.readouterr().out
