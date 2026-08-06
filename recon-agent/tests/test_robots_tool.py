from recon_agent.tools import robots_tool
from recon_agent.tools.robots_tool import FetchResult


def test_parse_disallow_extracts_paths():
    text = "User-agent: *\nDisallow: /admin\nDisallow: /private/\nAllow: /public\n"
    assert robots_tool._parse_disallow(text) == ["/admin", "/private/"]


def test_analyze_disallowed_flags_sensitive_hints():
    findings = robots_tool.analyze_disallowed(["/admin/", "/public/"])
    assert len(findings) == 1
    assert "admin" in findings[0].detail.lower()
    assert "public" not in findings[0].detail.lower()


def test_analyze_disallowed_no_findings_when_nothing_sensitive():
    assert robots_tool.analyze_disallowed(["/search", "/tmp"]) == []


def test_run_uses_injected_fetch_fn_and_builds_robots_url():
    seen_urls = []

    def fake_fetch(url):
        seen_urls.append(url)
        return FetchResult(status_code=200, text="Disallow: /wp-admin/\n")

    result = robots_tool.run("https://example.com", fetch_fn=fake_fetch)
    assert seen_urls == ["https://example.com/robots.txt"]
    assert result.data["disallowed"] == ["/wp-admin/"]
    assert result.findings[0].title == "robots.txt discloses sensitive-looking paths"


def test_run_handles_non_200_status_with_no_findings():
    def fake_fetch(url):
        return FetchResult(status_code=404, text="")

    result = robots_tool.run("https://example.com", fetch_fn=fake_fetch)
    assert result.data["status_code"] == 404
    assert result.findings == []


def test_run_handles_fetch_failure_gracefully():
    def broken_fetch(url):
        raise ConnectionError("dns failure")

    result = robots_tool.run("https://example.com", fetch_fn=broken_fetch)
    assert result.data["error"] == "dns failure"
    assert result.findings == []
