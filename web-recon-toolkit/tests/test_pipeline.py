from datetime import datetime, timedelta, timezone

from webrecon.http_probe import HttpResponse
from webrecon.pipeline import analyze, scan


def fake_transport_factory(response: HttpResponse):
    def transport(url, timeout):
        return response
    return transport


def fake_cert_fetcher_factory(days_until_expiry: int):
    def fetcher(host, port, timeout):
        not_after = (datetime.now(timezone.utc) + timedelta(days=days_until_expiry)).strftime(
            "%b %d %H:%M:%S %Y"
        ) + " GMT"
        return {
            "notAfter": not_after,
            "subject": ((("commonName", host),),),
            "issuer": ((("organizationName", "Test CA"),),),
            "_protocol_version": "TLSv1.3",
        }
    return fetcher


def test_scan_aggregates_headers_tls_and_fingerprint():
    response = HttpResponse(
        url="https://example.test",
        status_code=200,
        headers={"Server": "nginx", "X-Powered-By": "PHP"},
        body="<div class='wp-content'>hi</div>",
        elapsed_ms=12.3,
    )
    result = scan(
        "https://example.test",
        transport=fake_transport_factory(response),
        cert_fetcher=fake_cert_fetcher_factory(days_until_expiry=180),
    )

    assert result["http"]["status_code"] == 200
    assert result["security_headers"]["grade"] in "ABCDEF"
    assert 179 <= result["tls"]["days_until_expiry"] <= 180
    assert result["tls_findings"] == []
    names = {t["name"] for t in result["technologies"]}
    assert "nginx" in names
    assert "WordPress" in names
    assert result["risk_score"] is not None
    assert result["risk_grade"] in "ABCDEF"


def test_scan_flags_soon_to_expire_certificate():
    response = HttpResponse(url="https://example.test", status_code=200, headers={}, body="", elapsed_ms=1.0)
    result = scan(
        "https://example.test",
        transport=fake_transport_factory(response),
        cert_fetcher=fake_cert_fetcher_factory(days_until_expiry=5),
    )

    severities = {f["severity"] for f in result["tls_findings"]}
    assert "high" in severities


def test_scan_flags_expired_certificate_as_critical():
    response = HttpResponse(url="https://example.test", status_code=200, headers={}, body="", elapsed_ms=1.0)
    result = scan(
        "https://example.test",
        transport=fake_transport_factory(response),
        cert_fetcher=fake_cert_fetcher_factory(days_until_expiry=-3),
    )

    severities = {f["severity"] for f in result["tls_findings"]}
    assert "critical" in severities
    assert result["risk_score"] < 100


def test_scan_does_not_flag_modern_tls_as_obsolete():
    # regression: "TLSv1" in "TLSv1.3" is True under naive substring matching
    response = HttpResponse(url="https://example.test", status_code=200, headers={}, body="", elapsed_ms=1.0)
    result = scan(
        "https://example.test",
        transport=fake_transport_factory(response),
        cert_fetcher=fake_cert_fetcher_factory(days_until_expiry=180),
    )
    assert result["tls"]["protocol_version"] == "TLSv1.3"
    assert result["tls_findings"] == []


def test_scan_skips_tls_when_requested():
    response = HttpResponse(url="https://example.test", status_code=200, headers={}, body="", elapsed_ms=1.0)
    result = scan(
        "https://example.test",
        transport=fake_transport_factory(response),
        cert_fetcher=fake_cert_fetcher_factory(days_until_expiry=180),
        skip_tls=True,
    )
    assert result["tls"] is None


def test_scan_http_target_has_no_tls_section():
    response = HttpResponse(url="http://example.test", status_code=200, headers={}, body="", elapsed_ms=1.0)
    result = scan("http://example.test", transport=fake_transport_factory(response))
    assert result["tls"] is None


def test_scan_surfaces_transport_error_without_crashing():
    response = HttpResponse(
        url="https://unreachable.test", status_code=0, headers={}, body="", elapsed_ms=0.0, error="timed out"
    )
    result = scan("https://unreachable.test", transport=fake_transport_factory(response))

    assert result["http"]["error"] == "timed out"
    assert result["security_headers"] is None
    assert result["risk_score"] is None


def test_analyze_offline_fixture_matches_scan_shape():
    fixture = {
        "url": "https://example.test",
        "status_code": 200,
        "headers": {"Server": "Apache"},
        "body": "no cms markers here",
        "elapsed_ms": 42.0,
        "tls": {
            "protocol_version": "TLSv1.2",
            "subject": "CN=example.test",
            "issuer": "CN=Test CA",
            "not_after": (datetime.now(timezone.utc) + timedelta(days=200)).strftime("%b %d %H:%M:%S %Y") + " GMT",
        },
    }

    result = analyze(fixture)

    assert result["target"] == "https://example.test"
    assert result["http"]["status_code"] == 200
    assert 199 <= result["tls"]["days_until_expiry"] <= 200
    assert any(t["name"] == "Apache HTTPD" for t in result["technologies"])
