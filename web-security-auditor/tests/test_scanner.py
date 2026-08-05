from websecaudit.fetcher import FetchResult, TLSInfo
from websecaudit.scanner import analyze

GOOD_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=()",
}


def test_analyze_fetch_error_yields_critical_finding_and_grade_f():
    fetch_result = FetchResult(
        requested_url="https://down.example",
        final_url="https://down.example",
        status_code=0,
        scheme="https",
        error="Connection refused",
    )
    result = analyze(fetch_result)
    assert result.grade == "F"
    assert result.score == 0
    assert len(result.findings) == 1
    assert result.findings[0].id == "fetch-failed"


def test_analyze_fully_hardened_site_scores_perfectly():
    fetch_result = FetchResult(
        requested_url="https://good.example",
        final_url="https://good.example",
        status_code=200,
        scheme="https",
        headers=GOOD_HEADERS,
        set_cookie_headers=["session=abc; Secure; HttpOnly; SameSite=Strict"],
        redirect_chain=[],
        tls=TLSInfo(protocol_version="TLSv1.3", days_until_expiry=200),
    )
    result = analyze(fetch_result)
    assert result.findings == []
    assert result.score == 100
    assert result.grade == "A+"


def test_analyze_weak_site_accumulates_findings_from_all_modules():
    fetch_result = FetchResult(
        requested_url="http://weak.example",
        final_url="http://weak.example",
        status_code=200,
        scheme="http",
        headers={},
        set_cookie_headers=["session=abc"],
        redirect_chain=[],
        tls=None,
    )
    result = analyze(fetch_result)
    categories = {f.category for f in result.findings}
    assert "header" in categories
    assert "cookie" in categories
    assert "transport" in categories
    assert result.grade != "A+"


def test_findings_are_sorted_by_severity_descending():
    fetch_result = FetchResult(
        requested_url="http://weak.example",
        final_url="http://weak.example",
        status_code=200,
        scheme="http",
        headers={},
        set_cookie_headers=[],
        redirect_chain=[],
        tls=None,
    )
    result = analyze(fetch_result)
    severities = [f.severity for f in result.findings]
    from websecaudit.findings import SEVERITY_RANK

    ranks = [SEVERITY_RANK[s] for s in severities]
    assert ranks == sorted(ranks, reverse=True)
