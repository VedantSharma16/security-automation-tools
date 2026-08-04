from __future__ import annotations

from phishing_triage.parser import EmailLink
from phishing_triage.url_analysis import analyze_links, analyze_url


def _link(href: str, display_text: str | None = None, source: str = "html") -> EmailLink:
    return EmailLink(href=href, display_text=display_text or href, source=source)


def test_benign_link_has_no_findings():
    finding = analyze_url(_link("https://github.com/example-org/repo/pull/1", "View pull request"))
    assert finding.weight == 0
    assert finding.reasons == ()
    assert finding.brand_impersonation is None


def test_ip_literal_host_flagged():
    finding = analyze_url(_link("http://203.0.113.9/login"))
    assert finding.is_ip_literal is True
    assert finding.weight > 0


def test_userinfo_spoofing_flagged():
    finding = analyze_url(_link("http://paypal.com@evil.tk/verify"))
    assert finding.is_userinfo_spoof is True
    assert finding.host == "evil.tk"
    assert any("userinfo" in r for r in finding.reasons)


def test_punycode_flagged():
    finding = analyze_url(_link("https://xn--pypal-4ve.com/login"))
    assert finding.is_punycode is True


def test_url_shortener_flagged():
    finding = analyze_url(_link("https://bit.ly/3xyz123"))
    assert finding.is_shortener is True


def test_suspicious_tld_flagged():
    finding = analyze_url(_link("https://account-verify.top/secure"))
    assert finding.suspicious_tld is True


def test_credential_path_keyword_flagged():
    finding = analyze_url(_link("https://example.com/account/login/verify"))
    assert finding.has_credential_keyword is True


def test_brand_impersonation_via_display_text():
    finding = analyze_url(_link("http://totally-not-paypal.tk/login", "www.paypal.com"))
    assert finding.brand_impersonation == "paypal"


def test_legit_brand_domain_is_not_flagged():
    finding = analyze_url(_link("https://www.paypal.com/signin", "www.paypal.com"))
    assert finding.brand_impersonation is None
    assert finding.display_href_mismatch is False


def test_display_href_mismatch_flagged():
    finding = analyze_url(_link("https://evil.example.net/x", "https://www.microsoft.com/login"))
    assert finding.display_href_mismatch is True


def test_subdomain_of_display_host_is_not_a_mismatch():
    finding = analyze_url(_link("https://accounts.google.com/signin", "google.com"))
    assert finding.display_href_mismatch is False


def test_analyze_links_maps_over_all_links():
    links = (
        _link("https://github.com/x", "x"),
        _link("http://a@evil.tk/y", "y"),
    )
    findings = analyze_links(links)
    assert len(findings) == 2
    assert findings[0].weight == 0
    assert findings[1].weight > 0
