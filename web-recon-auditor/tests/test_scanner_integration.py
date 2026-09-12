"""End-to-end scan against a real (local, in-process) HTTP server.

This exercises the full pipeline — fetching, header analysis, soft-404
baselining, and path probing — over an actual socket, without touching
any external host. Scanning 127.0.0.1, which this test itself stood up,
needs no third-party authorization.
"""

from webrecon.fetcher import Fetcher
from webrecon.scanner import scan_target


def test_full_scan_finds_header_and_path_issues(fixture_server):
    base_url, routes = fixture_server
    routes["admin"] = (200, {"Content-Type": "text/html"}, "<html>Admin Login</html>")
    routes[""] = (
        200,
        {"Content-Type": "text/html", "Server": "nginx/1.18.0", "Set-Cookie": "session=x; Path=/"},
        "<html>home</html>",
    )

    report = scan_target(base_url, fetcher=Fetcher(), check_tls=False)

    ids = {f.id for f in report.findings}
    assert "missing-hsts" not in ids  # plain http, HSTS check only applies to https
    assert "missing-csp" in ids
    assert "banner-disclosure-server" in ids
    assert "cookie-missing-flags-session" in ids
    assert "exposed-path-admin" in ids
    assert "missing-security-txt" in ids
    assert report.risk.score > 0
    assert report.errors == []


def test_full_scan_does_not_flag_paths_that_also_404(fixture_server):
    base_url, routes = fixture_server
    # Nothing overridden: every probed path (including sensitive ones) 404s
    # the same way the random canary does, so nothing should be "exposed".
    report = scan_target(base_url, fetcher=Fetcher(), check_tls=False)

    path_ids = {f.id for f in report.findings if f.category == "paths" and f.id != "missing-security-txt"}
    assert path_ids == set()


def test_unreachable_target_records_error_but_does_not_crash():
    report = scan_target("http://127.0.0.1:1", fetcher=Fetcher(timeout=1.0), check_tls=False)
    assert report.errors
    assert "Could not reach" in report.errors[0]
