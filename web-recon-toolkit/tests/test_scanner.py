import pytest

from webrecon.models import Severity
from webrecon.scanner import AuthorizationError, InvalidTargetError, scan_target


def test_refuses_to_run_without_authorization(test_server):
    with pytest.raises(AuthorizationError):
        scan_target(test_server.base_url, authorized=False)


def test_rejects_non_http_scheme():
    with pytest.raises(InvalidTargetError):
        scan_target("ftp://example.test", authorized=True)


def test_rejects_url_with_no_host():
    with pytest.raises(InvalidTargetError):
        scan_target("http://", authorized=True)


def test_unreachable_host_records_error_instead_of_raising():
    # Port 1 is reserved and nothing will be listening there.
    result = scan_target("http://127.0.0.1:1", authorized=True, timeout=1)
    assert result.errors
    assert result.findings == []


def test_full_scan_against_hardened_server_has_no_header_findings(test_server):
    test_server.set_routes(
        {
            "/": {
                "status": 200,
                "body": b"<html><body>ok</body></html>",
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
    result = scan_target(test_server.base_url, authorized=True, timeout=3)
    header_findings = [f for f in result.findings if f.category == "headers"]
    assert header_findings == []
    assert result.errors == []


def test_full_scan_flags_missing_headers_and_exposed_secret(test_server):
    test_server.set_routes(
        {
            "/": {"status": 200, "body": b"<html>hi</html>", "headers": {"Server": "Apache/2.4.29"}},
            "/.env": {"status": 200, "body": b"DB_PASSWORD=hunter2\nAPI_KEY=xyz\n", "headers": {}},
            "__default__": {"status": 404, "body": b"not found", "headers": {}},
        }
    )
    result = scan_target(test_server.base_url, authorized=True, timeout=3)

    ids = {f.id for f in result.findings}
    assert "header-missing-content-security-policy" in ids
    assert "disclosure-server" in ids
    assert "path-.env" in ids

    env_finding = next(f for f in result.findings if f.id == "path-.env")
    assert env_finding.severity == Severity.CRITICAL


def test_insecure_cookie_flagged_end_to_end(test_server):
    test_server.set_routes(
        {
            "/": {
                "status": 200,
                "body": b"<html>hi</html>",
                "headers": {},
                "set_cookies": ["sessionid=abc123; Path=/"],
            },
            "__default__": {"status": 404, "body": b"not found", "headers": {}},
        }
    )
    result = scan_target(test_server.base_url, authorized=True, timeout=3)
    cookie_findings = [f for f in result.findings if f.category == "cookies"]
    assert len(cookie_findings) == 1
