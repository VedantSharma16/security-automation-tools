from webrecon import cli
from webrecon.tls_check import TLSReport, TLSFinding


class FakeResponse:
    def __init__(self, headers=None, text="", status_code=200):
        self.headers = headers or {}
        self.text = text
        self.status_code = status_code
        self.raw = None


class FakeSession:
    """Minimal stand-in for `requests` used by `run()`, keyed by exact URL."""

    def __init__(self, responses):
        self.responses = responses
        self.requested_urls = []

    def get(self, url, timeout=None, allow_redirects=True):
        self.requested_urls.append(url)
        if url not in self.responses:
            raise Exception(f"unexpected request to {url}")
        return self.responses[url]


def healthy_tls_report():
    return TLSReport(
        subject_cn="example.com",
        issuer_cn="Some CA",
        not_before=None,
        not_after=None,
        protocol_version="TLSv1.3",
        days_until_expiry=200,
        findings=(TLSFinding("info", "fine"),),
    )


def test_main_refuses_without_authorization_flag(capsys):
    exit_code = cli.main(["example.com"])
    assert exit_code == cli.EXIT_ERROR
    captured = capsys.readouterr()
    assert "Refusing to scan" in captured.err


def test_base_url_and_host_defaults_to_https():
    base_url, host = cli._base_url_and_host("example.com")
    assert base_url == "https://example.com"
    assert host == "example.com"


def test_base_url_and_host_respects_explicit_scheme():
    base_url, host = cli._base_url_and_host("http://example.com:8080/path")
    assert base_url == "http://example.com:8080"
    assert host == "example.com"


def test_run_builds_report_from_mocked_http_and_tls(monkeypatch):
    session = FakeSession(
        {
            "https://example.com": FakeResponse(headers={"Server": "nginx"}, text="<html></html>"),
            "https://example.com/robots.txt": FakeResponse(text="Disallow: /admin\n", status_code=200),
        }
    )
    monkeypatch.setattr(cli.tls_check, "fetch_certificate", lambda host, timeout=5.0: ({}, "TLSv1.3"))
    monkeypatch.setattr(cli.tls_check, "inspect_certificate", lambda cert, proto: healthy_tls_report())

    parser = cli.build_parser()
    args = parser.parse_args(["example.com", "--i-own-this-target"])

    report = cli.run(args, session=session)

    assert report.target == "https://example.com"
    assert any(t.name == "nginx" for t in report.technologies)
    assert report.robots_findings.sensitive_paths == ("/admin",)
    assert report.errors == []


def test_run_records_error_when_http_fetch_fails(monkeypatch):
    class FailingSession:
        def get(self, *a, **kw):
            import requests

            raise requests.ConnectionError("connection refused")

    monkeypatch.setattr(cli.tls_check, "fetch_certificate", lambda host, timeout=5.0: (_ for _ in ()).throw(OSError("no route")))

    parser = cli.build_parser()
    args = parser.parse_args(["example.com", "--i-own-this-target"])

    report = cli.run(args, session=FailingSession())

    assert any("HTTP fetch" in e for e in report.errors)
    assert any("TLS check failed" in e for e in report.errors)


def test_main_exit_code_reflects_findings(monkeypatch, capsys):
    session = FakeSession(
        {
            "https://example.com": FakeResponse(headers={}, text=""),
            "https://example.com/robots.txt": FakeResponse(text="", status_code=404),
        }
    )
    monkeypatch.setattr(cli, "run", lambda args, session=None: cli.report_mod.build_report(
        target="https://example.com",
        header_findings=[],
        tls_report=healthy_tls_report(),
    ))

    exit_code = cli.main(["example.com", "--i-own-this-target", "--no-color"])
    assert exit_code == cli.EXIT_CLEAN
