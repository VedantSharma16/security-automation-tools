from __future__ import annotations

from conftest import make_result

from asmapper.robots import parse_robots, scan


def test_parse_robots_extracts_disallow_and_allow_paths():
    body = """
    # comment
    User-agent: *
    Disallow: /
    Disallow: /admin/
    Disallow: /wp-admin/
    Allow: /public/
    """
    paths = parse_robots(body)
    assert "/admin/" in paths
    assert "/wp-admin/" in paths
    assert "/public/" in paths
    assert "/" not in paths  # bare wildcard disallow is not "interesting"


def test_scan_reports_nothing_when_robots_missing(fake_fetcher):
    findings = scan("https://example.com", fetch_fn=fake_fetcher)
    assert findings == []


def test_scan_flags_sensitive_looking_paths(fake_fetcher):
    fake_fetcher.register(
        "https://example.com/robots.txt",
        make_result(
            "https://example.com/robots.txt",
            body="User-agent: *\nDisallow: /admin/\nDisallow: /public/\nDisallow: /.git/\n",
        ),
    )
    findings = scan("https://example.com", fetch_fn=fake_fetcher)
    ids = {f.id for f in findings}
    assert "robots-txt-present" in ids
    assert "robots-txt-sensitive-paths" in ids
    sensitive_finding = next(f for f in findings if f.id == "robots-txt-sensitive-paths")
    assert "/admin/" in sensitive_finding.detail
    assert "/.git/" in sensitive_finding.detail


def test_scan_with_only_non_sensitive_paths_skips_sensitive_finding(fake_fetcher):
    fake_fetcher.register(
        "https://example.com/robots.txt",
        make_result("https://example.com/robots.txt", body="User-agent: *\nDisallow: /gallery/\n"),
    )
    findings = scan("https://example.com", fetch_fn=fake_fetcher)
    ids = {f.id for f in findings}
    assert "robots-txt-present" in ids
    assert "robots-txt-sensitive-paths" not in ids


def test_scan_reports_sitemap_url_count(fake_fetcher):
    sitemap_body = "<urlset><url><loc>https://example.com/a</loc></url><url><loc>https://example.com/b</loc></url></urlset>"
    fake_fetcher.register(
        "https://example.com/sitemap.xml",
        make_result("https://example.com/sitemap.xml", body=sitemap_body),
    )
    findings = scan("https://example.com", fetch_fn=fake_fetcher)
    sitemap_finding = next(f for f in findings if f.id == "sitemap-xml-present")
    assert "2 URL" in sitemap_finding.title
