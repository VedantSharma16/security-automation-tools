from recon_assistant.http_audit import audit_headers, audit_open_ports


def fetch_with(headers: dict[str, str], status: int = 200):
    def fetch_fn(host, port, use_tls):
        return status, headers

    return fetch_fn


def test_plaintext_http_flagged():
    findings = audit_headers("host", 80, False, fetch_fn=fetch_with({}))
    assert any(f.type == "missing_transport_security" for f in findings)


def test_https_missing_hsts_flagged():
    findings = audit_headers("host", 443, True, fetch_fn=fetch_with({}))
    assert any(f.title == "Missing Strict-Transport-Security" for f in findings)


def test_https_with_all_headers_has_no_missing_header_findings():
    headers = {
        "strict-transport-security": "max-age=63072000",
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "server": "myserver",
    }
    findings = audit_headers("host", 443, True, fetch_fn=fetch_with(headers))
    assert findings == []


def test_csp_present_suppresses_frame_options_finding():
    headers = {
        "strict-transport-security": "max-age=1",
        "content-security-policy": "frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
    }
    findings = audit_headers("host", 443, True, fetch_fn=fetch_with(headers))
    assert not any(f.title == "Missing X-Frame-Options" for f in findings)


def test_verbose_server_header_flagged():
    headers = {
        "strict-transport-security": "max-age=1",
        "content-security-policy": "x",
        "x-content-type-options": "nosniff",
        "referrer-policy": "x",
        "server": "Apache/2.4.49",
    }
    findings = audit_headers("host", 443, True, fetch_fn=fetch_with(headers))
    assert any(f.type == "information_disclosure" for f in findings)


def test_connection_error_returns_no_findings():
    def fetch_fn(host, port, use_tls):
        raise OSError("connection reset")

    assert audit_headers("host", 443, True, fetch_fn=fetch_fn) == []


def test_audit_open_ports_only_checks_web_ports():
    calls = []

    def fetch_fn(host, port, use_tls):
        calls.append(port)
        return 200, {}

    audit_open_ports("host", [22, 80, 3306], fetch_fn=fetch_fn)
    assert calls == [80]
