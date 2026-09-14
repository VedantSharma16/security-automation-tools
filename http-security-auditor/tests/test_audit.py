from http_audit.audit import run_audit
from http_audit.fetcher import HttpResponse
from http_audit.llm_narrative import LLMNarrator


def _fake_transport_hardened(url: str) -> HttpResponse:
    return HttpResponse(
        url=url,
        status=200,
        headers={
            "strict-transport-security": "max-age=63072000; includeSubDomains",
            "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "geolocation=()",
        },
        set_cookie_headers=["session=abc; Secure; HttpOnly; SameSite=Strict"],
    )


def _fake_transport_weak(url: str) -> HttpResponse:
    return HttpResponse(url=url, status=200, headers={}, set_cookie_headers=["session=abc"])


def test_hardened_site_scores_perfectly():
    report = run_audit("https://example.com/", transport=_fake_transport_hardened, narrator=LLMNarrator(api_key=None))
    assert report.score == 100
    assert report.grade == "A"
    assert report.status_code == 200
    assert report.llm_backed is False


def test_weak_site_scores_poorly_and_has_findings():
    report = run_audit("https://example.com/", transport=_fake_transport_weak, narrator=LLMNarrator(api_key=None))
    assert report.score < 100
    assert report.grade in ("D", "F", "C")
    assert any(f.severity in ("critical", "high") for f in report.findings)


def test_check_exposed_adds_exposure_findings():
    def transport(url: str) -> HttpResponse:
        if url == "https://example.com/":
            return _fake_transport_hardened(url)
        if url.endswith("/.git/HEAD"):
            return HttpResponse(url=url, status=200)
        return HttpResponse(url=url, status=404)

    report = run_audit(
        "https://example.com/",
        transport=transport,
        check_exposed=True,
        narrator=LLMNarrator(api_key=None),
    )
    exposure_findings = [f for f in report.findings if f.category == "exposure"]
    assert len(exposure_findings) == 1
    assert exposure_findings[0].severity == "critical"


def test_check_exposed_false_by_default_skips_extra_requests():
    calls = []

    def transport(url: str) -> HttpResponse:
        calls.append(url)
        return _fake_transport_hardened(url)

    run_audit("https://example.com/", transport=transport, narrator=LLMNarrator(api_key=None))
    assert calls == ["https://example.com/"]


def test_report_to_dict_and_markdown_round_trip():
    report = run_audit("https://example.com/", transport=_fake_transport_weak, narrator=LLMNarrator(api_key=None))
    as_dict = report.to_dict()
    assert as_dict["url"] == "https://example.com/"
    assert isinstance(as_dict["findings"], list)

    markdown = report.to_markdown()
    assert "# HTTP Security Audit" in markdown
    assert report.grade in markdown
