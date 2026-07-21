from webscan.checks.headers import check_security_headers
from webscan.models import ScanTarget

FULL_GOOD_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=()",
}


def _target(headers: dict, scheme: str = "https") -> ScanTarget:
    url = f"{scheme}://example.com/"
    return ScanTarget(url=url, final_url=url, status_code=200, headers=headers, raw_headers=list(headers.items()))


def test_no_findings_when_all_headers_present():
    assert check_security_headers(_target(FULL_GOOD_HEADERS)) == []


def test_missing_hsts_on_https():
    headers = dict(FULL_GOOD_HEADERS)
    del headers["strict-transport-security"]
    findings = check_security_headers(_target(headers))
    ids = [f.id for f in findings]
    assert "headers-hsts-missing" in ids


def test_hsts_not_required_on_plain_http():
    headers = dict(FULL_GOOD_HEADERS)
    del headers["strict-transport-security"]
    findings = check_security_headers(_target(headers, scheme="http"))
    assert "headers-hsts-missing" not in [f.id for f in findings]


def test_hsts_weak_max_age():
    headers = dict(FULL_GOOD_HEADERS)
    headers["strict-transport-security"] = "max-age=3600"
    findings = check_security_headers(_target(headers))
    ids = [f.id for f in findings]
    assert "headers-hsts-weak-max-age" in ids


def test_missing_csp():
    headers = dict(FULL_GOOD_HEADERS)
    del headers["content-security-policy"]
    findings = check_security_headers(_target(headers))
    assert "headers-csp-missing" in [f.id for f in findings]


def test_csp_unsafe_inline_flagged():
    headers = dict(FULL_GOOD_HEADERS)
    headers["content-security-policy"] = "default-src 'self'; script-src 'unsafe-inline'"
    findings = check_security_headers(_target(headers))
    assert "headers-csp-unsafe-directives" in [f.id for f in findings]


def test_missing_x_content_type_options():
    headers = dict(FULL_GOOD_HEADERS)
    del headers["x-content-type-options"]
    findings = check_security_headers(_target(headers))
    assert "headers-content-type-options-missing" in [f.id for f in findings]


def test_clickjacking_protection_via_csp_frame_ancestors_is_sufficient():
    headers = dict(FULL_GOOD_HEADERS)
    del headers["x-frame-options"]
    headers["content-security-policy"] = "default-src 'self'; frame-ancestors 'none'"
    findings = check_security_headers(_target(headers))
    assert "headers-clickjacking-protection-missing" not in [f.id for f in findings]


def test_missing_clickjacking_protection():
    headers = dict(FULL_GOOD_HEADERS)
    del headers["x-frame-options"]
    findings = check_security_headers(_target(headers))
    assert "headers-clickjacking-protection-missing" in [f.id for f in findings]


def test_missing_referrer_policy():
    headers = dict(FULL_GOOD_HEADERS)
    del headers["referrer-policy"]
    findings = check_security_headers(_target(headers))
    assert "headers-referrer-policy-missing" in [f.id for f in findings]


def test_missing_permissions_policy_is_info_severity():
    headers = dict(FULL_GOOD_HEADERS)
    del headers["permissions-policy"]
    findings = check_security_headers(_target(headers))
    matches = [f for f in findings if f.id == "headers-permissions-policy-missing"]
    assert len(matches) == 1
    assert matches[0].severity == "info"
