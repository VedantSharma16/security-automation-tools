import json

from webrecon.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, main


def test_cli_refuses_without_authorization_flag(capsys):
    exit_code = main(["http://example.test"])
    assert exit_code == EXIT_ERROR
    assert "--i-have-authorization" in capsys.readouterr().err


def test_cli_rejects_bad_scheme(capsys):
    exit_code = main(["ftp://example.test", "--i-have-authorization"])
    assert exit_code == EXIT_ERROR
    assert "error:" in capsys.readouterr().err


def test_cli_reports_findings_on_hardened_local_server(test_server, capsys):
    test_server.set_routes(
        {
            "/": {
                "status": 200,
                "body": b"ok",
                "headers": {
                    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                    "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "no-referrer",
                    "Permissions-Policy": "geolocation=()",
                },
            },
            "__default__": {"status": 404, "body": b"not found", "headers": {}},
        }
    )
    exit_code = main(
        [test_server.base_url, "--i-have-authorization", "--format", "json", "--timeout", "3"]
    )
    out = capsys.readouterr().out
    report = json.loads(out)
    assert report["summary"]["total_findings"] == 0
    assert exit_code == EXIT_CLEAN


def test_cli_writes_report_to_file(test_server, tmp_path):
    test_server.set_routes({"__default__": {"status": 404, "body": b"nf", "headers": {}}})
    out_file = tmp_path / "report.md"
    exit_code = main(
        [
            test_server.base_url,
            "--i-have-authorization",
            "--out",
            str(out_file),
            "--timeout",
            "3",
        ]
    )
    assert exit_code == EXIT_FINDINGS
    content = out_file.read_text()
    assert "Web Recon Report" in content
