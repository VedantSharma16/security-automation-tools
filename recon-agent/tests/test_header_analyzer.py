from recon_agent.header_analyzer import analyze_headers
from recon_agent.models import ProbeResult


def _probe(url="https://example.com/", headers=None, ok=True, status_code=200):
    return ProbeResult(url=url, ok=ok, status_code=status_code, headers=headers or {})


def test_no_findings_when_probe_failed():
    probe = _probe(ok=False, status_code=None, headers={})
    assert analyze_headers(probe) == []


def test_fully_hardened_response_has_no_findings():
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Set-Cookie": "session=abc; Secure; HttpOnly; SameSite=Strict",
    }
    probe = _probe(headers=headers)
    assert analyze_headers(probe) == []


def test_missing_hsts_only_flagged_on_https():
    https_probe = _probe(url="https://example.com/", headers={})
    http_probe = _probe(url="http://example.com/", headers={})

    https_findings = {f.id for f in analyze_headers(https_probe)}
    http_findings = {f.id for f in analyze_headers(http_probe)}

    assert "hdr-no-hsts" in https_findings
    assert "hdr-no-hsts" not in http_findings


def test_missing_csp_flagged():
    probe = _probe(headers={"Strict-Transport-Security": "max-age=1"})
    findings = {f.id for f in analyze_headers(probe)}
    assert "hdr-no-csp" in findings


def test_invalid_xcto_flagged():
    probe = _probe(headers={"X-Content-Type-Options": "sniff-away"})
    findings = {f.id for f in analyze_headers(probe)}
    assert "hdr-no-xcto" in findings


def test_frame_protection_satisfied_by_csp_frame_ancestors():
    probe = _probe(headers={"Content-Security-Policy": "frame-ancestors 'none'"})
    findings = {f.id for f in analyze_headers(probe)}
    assert "hdr-no-frame-protection" not in findings


def test_frame_protection_missing_when_neither_present():
    probe = _probe(headers={})
    findings = {f.id for f in analyze_headers(probe)}
    assert "hdr-no-frame-protection" in findings


def test_server_version_disclosure():
    probe = _probe(headers={"Server": "Apache/2.4.41 (Ubuntu)"})
    findings = [f for f in analyze_headers(probe) if f.id == "hdr-server-version-disclosure"]
    assert len(findings) == 1
    assert "2.4.41" in findings[0].evidence


def test_generic_server_header_not_flagged_as_disclosure():
    probe = _probe(headers={"Server": "nginx"})
    findings = {f.id for f in analyze_headers(probe)}
    assert "hdr-server-version-disclosure" not in findings


def test_x_powered_by_disclosure():
    probe = _probe(headers={"X-Powered-By": "PHP/8.1.0"})
    findings = {f.id for f in analyze_headers(probe)}
    assert "hdr-powered-by-disclosure" in findings


def test_cors_wildcard_with_credentials_is_critical():
    probe = _probe(
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
    )
    findings = [f for f in analyze_headers(probe) if f.id == "hdr-cors-wildcard-with-credentials"]
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_cors_wildcard_without_credentials_is_low():
    probe = _probe(headers={"Access-Control-Allow-Origin": "*"})
    findings = [f for f in analyze_headers(probe) if f.id == "hdr-cors-wildcard"]
    assert len(findings) == 1
    assert findings[0].severity == "low"


def test_cookie_missing_flags_only_on_https():
    headers = {"Set-Cookie": "session=abc; Path=/"}
    https_findings = {f.id for f in analyze_headers(_probe(url="https://example.com/", headers=headers))}
    http_findings = {f.id for f in analyze_headers(_probe(url="http://example.com/", headers=headers))}

    assert "hdr-cookie-missing-flags" in https_findings
    assert "hdr-cookie-missing-flags" not in http_findings


def test_cookie_with_all_flags_not_flagged():
    headers = {"Set-Cookie": "session=abc; Secure; HttpOnly; SameSite=Lax"}
    findings = {f.id for f in analyze_headers(_probe(headers=headers))}
    assert "hdr-cookie-missing-flags" not in findings


def test_header_lookup_is_case_insensitive():
    probe = _probe(headers={"strict-transport-security": "max-age=1"})
    findings = {f.id for f in analyze_headers(probe)}
    assert "hdr-no-hsts" not in findings
