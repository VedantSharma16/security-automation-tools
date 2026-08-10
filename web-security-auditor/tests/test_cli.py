import json

from webauditor import cli
from webauditor.fetcher import FetchResult

EMPTY_BY_SEVERITY = {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}


def make_fetch_result(ok=True, status_code=200, headers=None, set_cookie_headers=None):
    return FetchResult(
        url="https://example.com", final_url="https://example.com",
        status_code=status_code if ok else 0,
        headers=headers or {}, elapsed_seconds=0.01,
        error=None if ok else "connection refused",
        set_cookie_headers=set_cookie_headers or [],
    )


def test_main_without_authorized_flag_refuses_to_run(capsys):
    exit_code = cli.main(["https://example.com"])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "authorized" in captured.err.lower()


def test_main_with_authorized_flag_invokes_audit(monkeypatch, capsys):
    fake_report = {
        "target": "https://example.com",
        "generated_at": "now",
        "summary": {"total_findings": 0, "by_severity": EMPTY_BY_SEVERITY, "risk_score": 0,
                    "risk_rating": "GOOD", "highest_severity": None},
        "findings": [],
    }
    monkeypatch.setattr(cli, "run_audit", lambda *a, **k: fake_report)

    exit_code = cli.main(["https://example.com", "--authorized"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "example.com" in captured.out


def test_main_quiet_suppresses_console_output(monkeypatch, capsys):
    fake_report = {
        "target": "https://example.com", "generated_at": "now",
        "summary": {"total_findings": 0, "by_severity": EMPTY_BY_SEVERITY, "risk_score": 0,
                    "risk_rating": "GOOD", "highest_severity": None},
        "findings": [],
    }
    monkeypatch.setattr(cli, "run_audit", lambda *a, **k: fake_report)

    cli.main(["https://example.com", "--authorized", "--quiet"])
    captured = capsys.readouterr()
    assert captured.out == ""


def test_main_writes_json_report_to_file(monkeypatch, tmp_path):
    fake_report = {
        "target": "https://example.com", "generated_at": "now",
        "summary": {"total_findings": 0, "by_severity": EMPTY_BY_SEVERITY, "risk_score": 0,
                    "risk_rating": "GOOD", "highest_severity": None},
        "findings": [],
    }
    monkeypatch.setattr(cli, "run_audit", lambda *a, **k: fake_report)
    out_path = tmp_path / "report.json"

    cli.main(["https://example.com", "--authorized", "--json", str(out_path), "--quiet"])

    assert json.loads(out_path.read_text()) == fake_report


def test_main_exit_code_reflects_high_severity_findings(monkeypatch, capsys):
    fake_report = {
        "target": "https://example.com", "generated_at": "now",
        "summary": {"total_findings": 1, "by_severity": EMPTY_BY_SEVERITY, "risk_score": 40,
                    "risk_rating": "POOR", "highest_severity": "HIGH"},
        "findings": [],
    }
    monkeypatch.setattr(cli, "run_audit", lambda *a, **k: fake_report)

    exit_code = cli.main(["https://example.com", "--authorized"])
    assert exit_code == 1


def test_run_audit_prepends_https_scheme_when_missing(monkeypatch):
    seen = {}

    def fake_fetch(url, timeout=10, session=None):
        seen["url"] = url
        return make_fetch_result(ok=True)

    monkeypatch.setattr(cli, "fetch", fake_fetch)
    monkeypatch.setattr(cli.headers, "analyze_security_headers", lambda h: [])
    monkeypatch.setattr(cli.headers, "analyze_cookies", lambda c: [])
    monkeypatch.setattr(cli.exposure, "check_exposed_paths", lambda base, fn: [])

    result = cli.run_audit("example.com", skip_tls=True, skip_exposure=True)
    assert seen["url"] == "https://example.com"
    assert result["target"] == "https://example.com"


def test_run_audit_reports_connection_failure(monkeypatch):
    monkeypatch.setattr(cli, "fetch", lambda url, timeout=10, session=None: make_fetch_result(ok=False))

    result = cli.run_audit("https://unreachable.example", skip_tls=True, skip_exposure=True)
    assert result["summary"]["total_findings"] == 1
    assert result["findings"][0]["id"] == "CONN-FAILED"


def test_run_audit_skips_tls_and_exposure_when_requested(monkeypatch):
    calls = {"tls": 0, "exposure": 0}
    monkeypatch.setattr(cli, "fetch", lambda url, timeout=10, session=None: make_fetch_result(ok=True))
    monkeypatch.setattr(cli.headers, "analyze_security_headers", lambda h: [])
    monkeypatch.setattr(cli.headers, "analyze_cookies", lambda c: [])
    monkeypatch.setattr(cli.tls_check, "check_tls", lambda *a, **k: calls.__setitem__("tls", calls["tls"] + 1) or [])
    monkeypatch.setattr(cli.exposure, "check_exposed_paths",
                         lambda *a, **k: calls.__setitem__("exposure", calls["exposure"] + 1) or [])

    cli.run_audit("https://example.com", skip_tls=True, skip_exposure=True)
    assert calls == {"tls": 0, "exposure": 0}


def test_run_audit_runs_tls_and_exposure_by_default(monkeypatch):
    calls = {"tls": 0, "exposure": 0}
    monkeypatch.setattr(cli, "fetch", lambda url, timeout=10, session=None: make_fetch_result(ok=True))
    monkeypatch.setattr(cli.headers, "analyze_security_headers", lambda h: [])
    monkeypatch.setattr(cli.headers, "analyze_cookies", lambda c: [])
    monkeypatch.setattr(cli.tls_check, "check_tls", lambda *a, **k: calls.__setitem__("tls", calls["tls"] + 1) or [])
    monkeypatch.setattr(cli.exposure, "check_exposed_paths",
                         lambda *a, **k: calls.__setitem__("exposure", calls["exposure"] + 1) or [])

    cli.run_audit("https://example.com")
    assert calls == {"tls": 1, "exposure": 1}
