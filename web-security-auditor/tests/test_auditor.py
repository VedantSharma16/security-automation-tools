from webauditor import auditor
from webauditor.fetcher import FetchResult
from webauditor.models import Severity
from webauditor.tls_inspector import TLSInfo


def _hardened_https_response():
    return FetchResult(
        url="https://example.com/",
        final_url="https://example.com/",
        status=200,
        headers=[
            ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
            ("Content-Security-Policy", "default-src 'self'"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
            ("Permissions-Policy", "geolocation=()"),
        ],
    )


def test_audit_url_combines_headers_and_tls(monkeypatch):
    monkeypatch.setattr(auditor, "fetch", lambda url, timeout=10.0: _hardened_https_response())
    monkeypatch.setattr(
        auditor,
        "inspect_tls",
        lambda host, port, timeout=10.0: TLSInfo(
            host=host, port=port, protocol="TLSv1.3", cipher="X", days_until_expiry=200, not_after="n/a",
        ),
    )

    result = auditor.audit_url("https://example.com/")

    assert result.grade == "A"
    assert result.score == 100
    assert result.tls_info is not None
    assert result.tls_info.protocol == "TLSv1.3"


def test_audit_url_skip_tls_does_not_call_inspector(monkeypatch):
    monkeypatch.setattr(auditor, "fetch", lambda url, timeout=10.0: _hardened_https_response())
    called = []
    monkeypatch.setattr(auditor, "inspect_tls", lambda *a, **k: called.append(1))

    result = auditor.audit_url("https://example.com/", skip_tls=True)

    assert result.tls_info is None
    assert not called


def test_audit_url_reports_fetch_failure_as_critical_finding(monkeypatch):
    failed = FetchResult(url="https://down.example/", final_url="https://down.example/", status=0, error="Connection refused")
    monkeypatch.setattr(auditor, "fetch", lambda url, timeout=10.0: failed)

    result = auditor.audit_url("https://down.example/", skip_tls=True)

    assert any(f.check_id == "fetch-error" and f.severity == Severity.CRITICAL for f in result.findings)
    # Header checks should not run against a response we never got.
    assert not any(f.check_id == "hsts" for f in result.findings)


def test_audit_url_http_scheme_skips_tls_inspection(monkeypatch):
    response = FetchResult(url="http://example.com/", final_url="http://example.com/", status=200, headers=[])
    monkeypatch.setattr(auditor, "fetch", lambda url, timeout=10.0: response)
    called = []
    monkeypatch.setattr(auditor, "inspect_tls", lambda *a, **k: called.append(1))

    result = auditor.audit_url("http://example.com/")

    assert result.tls_info is None
    assert not called
