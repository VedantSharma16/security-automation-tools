import urllib.error

from recon_agent.tools import ToolBox


def test_dns_lookup_success():
    toolbox = ToolBox(resolve=lambda host: ["93.184.216.34"])
    result = toolbox.dns_lookup("example.com")
    assert result.ok
    assert result.data["addresses"] == ["93.184.216.34"]


def test_dns_lookup_failure():
    def fail(host):
        raise OSError("name resolution failed")

    toolbox = ToolBox(resolve=fail)
    result = toolbox.dns_lookup("nonexistent.invalid")
    assert not result.ok
    assert "name resolution failed" in result.error


def test_fetch_headers_success_caches_headers_scheme_and_port():
    def fake_get(url, timeout):
        return 200, {"Content-Type": "text/html", "Server": "nginx"}, b"<html></html>"

    toolbox = ToolBox(http_get=fake_get)
    result = toolbox.fetch_headers("https://example.com:8443/")
    assert result.ok
    assert result.data["status"] == 200
    assert toolbox._last_headers["Server"] == "nginx"
    assert toolbox._last_scheme == "https"
    assert toolbox._last_port == 8443


def test_fetch_headers_http_error_still_captures_status():
    def fake_get(url, timeout):
        raise urllib.error.HTTPError(url, 404, "Not Found", hdrs={"X-Test": "1"}, fp=None)

    toolbox = ToolBox(http_get=fake_get)
    result = toolbox.fetch_headers("https://example.com/missing")
    assert result.ok
    assert result.data["status"] == 404


def test_fetch_headers_connection_error():
    def fake_get(url, timeout):
        raise urllib.error.URLError("connection refused")

    toolbox = ToolBox(http_get=fake_get)
    result = toolbox.fetch_headers("https://unreachable.example")
    assert not result.ok
    assert result.error


def test_fetch_robots_txt_parses_disallowed_paths():
    body = b"User-agent: *\nDisallow: /admin\nDisallow: /private\n# comment\nAllow: /public\n"

    def fake_get(url, timeout):
        assert url.endswith("/robots.txt")
        return 200, {}, body

    toolbox = ToolBox(http_get=fake_get)
    result = toolbox.fetch_robots_txt("https://example.com/some/page")
    assert result.ok
    assert result.data["disallowed_paths"] == ["/admin", "/private"]


def test_fetch_robots_txt_missing_is_not_an_error():
    def fake_get(url, timeout):
        raise urllib.error.HTTPError(url, 404, "Not Found", hdrs=None, fp=None)

    toolbox = ToolBox(http_get=fake_get)
    result = toolbox.fetch_robots_txt("https://example.com/")
    assert result.ok
    assert result.data["disallowed_paths"] == []


def test_grade_security_headers_uses_cached_headers_from_fetch():
    def fake_get(url, timeout):
        return 200, {"Content-Type": "text/html"}, b""

    toolbox = ToolBox(http_get=fake_get)
    toolbox.fetch_headers("https://example.com/")
    result = toolbox.grade_security_headers()
    assert result.ok
    assert result.data["score"] < 100


def test_grade_security_headers_without_prior_fetch_errors():
    toolbox = ToolBox()
    result = toolbox.grade_security_headers()
    assert not result.ok


def test_check_tls_success():
    toolbox = ToolBox(
        tls_info=lambda host, port, timeout: {"protocol": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256", "cert": {}}
    )
    result = toolbox.check_tls("example.com")
    assert result.ok
    assert result.data["protocol"] == "TLSv1.3"


def test_check_tls_failure():
    def fail(host, port, timeout):
        raise OSError("connection refused")

    toolbox = ToolBox(tls_info=fail)
    result = toolbox.check_tls("example.com")
    assert not result.ok


def test_port_scan_reports_open_and_closed():
    def fake_connect(host, port, timeout):
        return port in (80, 443)

    toolbox = ToolBox(tcp_connect=fake_connect)
    result = toolbox.port_scan("example.com", [22, 80, 443, 3389])
    assert result.ok
    assert set(result.data["open_ports"]) == {80, 443}


def test_port_scan_defaults_include_last_fetched_port():
    def fake_get(url, timeout):
        return 200, {}, b""

    toolbox = ToolBox(http_get=fake_get, tcp_connect=lambda host, port, timeout: False)
    toolbox.fetch_headers("https://example.com:9443/")
    result = toolbox.port_scan("example.com")
    assert 9443 in result.data["scanned"]
