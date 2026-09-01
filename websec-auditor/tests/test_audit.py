from datetime import datetime, timedelta, timezone

from tests.fakes import FakeOpener, FakeResponse
from websec_auditor.audit import run_audit
from websec_auditor.tls_check import TLSInfo


def good_tls_connector(hostname, port, timeout):
    return TLSInfo(
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        not_after=datetime.now(timezone.utc) + timedelta(days=200),
        not_before=datetime.now(timezone.utc) - timedelta(days=10),
        issuer="CN=Test CA",
        subject=f"CN={hostname}",
        san=[hostname],
    )


def test_run_audit_end_to_end_good_site():
    url = "https://good.example/"
    opener = FakeOpener(
        {
            url: FakeResponse(
                url,
                status=200,
                headers=[
                    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
                    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
                    ("X-Content-Type-Options", "nosniff"),
                    ("Referrer-Policy", "strict-origin-when-cross-origin"),
                    ("Permissions-Policy", "geolocation=()"),
                    ("Server", "nginx"),
                ],
                body=b"<html>ok</html>",
            )
        }
    )
    result = run_audit(url, opener=opener, tls_connector=good_tls_connector)
    assert result.status == 200
    assert result.grade == "A"
    assert result.score == 100
    assert result.fetch_error is None


def test_run_audit_flags_missing_everything_on_insecure_site():
    url = "https://bad.example/"
    opener = FakeOpener({url: FakeResponse(url, status=200, headers=[], body=b"")})
    result = run_audit(url, opener=opener, tls_connector=good_tls_connector)
    assert result.grade in ("D", "F")
    assert any(f.id == "missing-csp" for f in result.findings)


def test_run_audit_handles_unreachable_host():
    import urllib.error

    url = "https://down.example/"
    opener = FakeOpener({url: urllib.error.URLError("connection refused")})
    result = run_audit(url, opener=opener)
    assert result.grade == "F"
    assert result.fetch_error is not None
    assert any(f.id == "fetch-failed" for f in result.findings)


def test_run_audit_skip_tls_avoids_tls_check():
    calls = []

    def connector(hostname, port, timeout):
        calls.append(hostname)
        return good_tls_connector(hostname, port, timeout)

    url = "https://good.example/"
    opener = FakeOpener({url: FakeResponse(url, status=200, headers=[], body=b"")})
    run_audit(url, opener=opener, tls_connector=connector, skip_tls=True)
    assert calls == []


def test_run_audit_check_well_known_fetches_extra_paths():
    url = "https://good.example/"
    robots = "https://good.example/robots.txt"
    security = "https://good.example/.well-known/security.txt"
    opener = FakeOpener(
        {
            url: FakeResponse(url, status=200, headers=[], body=b""),
            robots: FakeResponse(robots, status=200),
            security: FakeResponse(security, status=404),
        }
    )
    result = run_audit(url, opener=opener, tls_connector=good_tls_connector, check_well_known=True)
    assert result.well_known == {"robots.txt": 200, ".well-known/security.txt": 404}


def test_http_url_skips_hsts_and_tls_findings():
    url = "http://plain.example/"
    opener = FakeOpener({url: FakeResponse(url, status=200, headers=[], body=b"")})
    result = run_audit(url, opener=opener)
    assert not any(f.id == "missing-hsts" for f in result.findings)
    assert not any(f.category == "tls" for f in result.findings)
