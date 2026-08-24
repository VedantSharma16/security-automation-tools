import json

import webauditor.cli as cli_mod
from webauditor.cli import EXIT_CLEAN, EXIT_FINDINGS, main
from webauditor.findings import Finding, Severity


def _patch_run_audit(monkeypatch, findings):
    monkeypatch.setattr(cli_mod, "run_audit", lambda *args, **kwargs: findings)


def test_main_exits_clean_when_no_findings(monkeypatch, capsys):
    _patch_run_audit(monkeypatch, [])

    exit_code = main(["https://example.com", "--no-color"])

    assert exit_code == EXIT_CLEAN
    assert "No findings" in capsys.readouterr().out


def test_main_exits_nonzero_when_findings_present(monkeypatch, capsys):
    findings = [
        Finding(
            id="missing-hsts",
            title="Missing Strict-Transport-Security header",
            severity=Severity.HIGH,
            owasp_category="A02:2021 Cryptographic Failures",
            description="desc",
        )
    ]
    _patch_run_audit(monkeypatch, findings)

    exit_code = main(["https://example.com", "--no-color"])

    assert exit_code == EXIT_FINDINGS
    assert "Missing Strict-Transport-Security" in capsys.readouterr().out


def test_min_severity_filters_output(monkeypatch, capsys):
    findings = [
        Finding(
            id="a",
            title="High issue",
            severity=Severity.HIGH,
            owasp_category="A05:2021",
            description="d",
        ),
        Finding(
            id="b",
            title="Info issue",
            severity=Severity.INFO,
            owasp_category="A05:2021",
            description="d",
        ),
    ]
    _patch_run_audit(monkeypatch, findings)

    main(["https://example.com", "--no-color", "--min-severity", "high"])

    out = capsys.readouterr().out
    assert "High issue" in out
    assert "Info issue" not in out


def test_writes_json_and_markdown_reports(tmp_path, monkeypatch):
    findings = [
        Finding(
            id="a",
            title="High issue",
            severity=Severity.HIGH,
            owasp_category="A05:2021",
            description="d",
        )
    ]
    _patch_run_audit(monkeypatch, findings)

    json_out = tmp_path / "report.json"
    md_out = tmp_path / "report.md"

    main(
        [
            "https://example.com",
            "--no-color",
            "--json-out",
            str(json_out),
            "--markdown-out",
            str(md_out),
        ]
    )

    assert json_out.exists()
    assert md_out.exists()
    data = json.loads(json_out.read_text())
    assert data["findings"][0]["id"] == "a"
    assert "High issue" in md_out.read_text()


def test_narrative_flag_uses_offline_fallback(monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    _patch_run_audit(monkeypatch, [])

    main(["https://example.com", "--no-color", "--narrative"])

    assert "offline heuristic summary" in capsys.readouterr().out


def test_invalid_url_scheme_returns_error_exit_code(monkeypatch):
    from webauditor.auditor import run_audit as real_run_audit

    monkeypatch.setattr(cli_mod, "run_audit", real_run_audit)

    exit_code = main(["ftp://example.com"])

    assert exit_code == 2
