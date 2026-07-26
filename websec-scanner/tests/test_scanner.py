from __future__ import annotations

from websec.scanner import Scanner


def test_passive_scan_finds_missing_headers_and_insecure_cookie(live_target):
    result = Scanner(live_target, active=False).scan()
    titles = {f.title for f in result.findings}
    assert "Missing Content-Security-Policy header" in titles
    assert "Cookie 'session_id' missing HttpOnly flag" in titles
    assert result.active_checks_run is False
    assert result.pages_crawled == 0


def test_passive_scan_finds_exposed_git_config(live_target):
    result = Scanner(live_target, active=False).scan()
    assert any("Exposed .git" in f.title for f in result.findings)


def test_passive_scan_surfaces_robots_disclosures(live_target):
    result = Scanner(live_target, active=False).scan()
    robots_findings = [f for f in result.findings if "robots.txt" in f.title]
    assert robots_findings
    assert "/admin" in robots_findings[0].detail


def test_secure_page_has_no_missing_header_findings(live_target):
    result = Scanner(f"{live_target}/secure", active=False).scan()
    header_findings = [f for f in result.findings if f.check == "headers"]
    # The werkzeug dev server itself still emits a version-bearing `Server`
    # header, which is a legitimate finding -- assert none of the app-level
    # "missing header" / clickjacking findings fired, not that the list is empty.
    assert not any(f.title.startswith("Missing") for f in header_findings)
    assert not any("clickjacking" in f.title for f in header_findings)


def test_active_scan_detects_xss_and_sqli(live_target):
    result = Scanner(live_target, active=True, max_pages=10).scan()
    assert result.active_checks_run is True
    assert result.pages_crawled > 0
    assert result.endpoints_tested > 0

    xss_findings = [f for f in result.findings if f.check == "reflected-xss"]
    sqli_findings = [f for f in result.findings if f.check == "sql-injection"]
    assert any("q" in f.title for f in xss_findings)
    assert any("id" in f.title for f in sqli_findings)


def test_invalid_scheme_rejected():
    import pytest

    with pytest.raises(ValueError):
        Scanner("ftp://example.test")


def test_unreachable_target_reports_connectivity_finding():
    result = Scanner("http://127.0.0.1:1").scan()
    assert len(result.findings) == 1
    assert result.findings[0].check == "connectivity"
