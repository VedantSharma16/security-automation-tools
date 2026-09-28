from phishtriage.urls import (
    analyze_urls,
    defang,
    extract_href_text_pairs,
    extract_urls,
    find_domain_like,
    get_host,
    has_excessive_subdomains,
    has_punycode,
    has_userinfo_trick,
    is_ip_literal_host,
    is_known_shortener,
    lookalike_brand,
)


def test_extract_urls_dedupes_and_preserves_order():
    text = "Visit https://example.com/a then https://example.org/b"
    html = '<a href="https://example.com/a">again</a>'
    urls = extract_urls(text, html)
    assert urls == ["https://example.com/a", "https://example.org/b"]


def test_extract_urls_strips_trailing_punctuation():
    urls = extract_urls("See https://example.com/path.", "")
    assert urls == ["https://example.com/path"]


def test_defang_neutralizes_scheme_and_dots():
    assert defang("http://evil.example.com/x") == "http[:]//evil[.]example[.]com/x"


def test_get_host_lowercases():
    assert get_host("https://EXAMPLE.com/Path") == "example.com"


def test_is_ip_literal_host():
    assert is_ip_literal_host("192.168.1.1") is True
    assert is_ip_literal_host("example.com") is False


def test_is_known_shortener():
    assert is_known_shortener("bit.ly") is True
    assert is_known_shortener("example.com") is False


def test_has_punycode():
    assert has_punycode("xn--pypal-4ve.com") is True
    assert has_punycode("paypal.com") is False


def test_has_userinfo_trick():
    assert has_userinfo_trick("http://paypal.com@evil.tld/") is True
    assert has_userinfo_trick("http://paypal.com/") is False


def test_has_excessive_subdomains():
    assert has_excessive_subdomains("a.b.c.evil.com") is True
    assert has_excessive_subdomains("www.example.com") is False


def test_lookalike_brand_flags_typosquat():
    assert lookalike_brand("paypa1.com") == "paypal.com"


def test_lookalike_brand_flags_substring_impersonation():
    assert lookalike_brand("paypal-secure-login.com") == "paypal.com"


def test_lookalike_brand_allows_real_domain_and_subdomains():
    assert lookalike_brand("paypal.com") is None
    assert lookalike_brand("www.paypal.com") is None
    assert lookalike_brand("login.paypal.com") is None


def test_lookalike_brand_none_for_unrelated_domain():
    assert lookalike_brand("example.com") is None


def test_analyze_urls_flags_multiple_reasons():
    findings = analyze_urls(
        ["http://paypa1-verify.com/login", "https://bit.ly/x", "https://example.com/fine"]
    )
    hosts = {f.host: f.reasons for f in findings}
    assert "paypa1-verify.com" in hosts
    assert any("impersonate" in r for r in hosts["paypa1-verify.com"])
    assert "bit.ly" in hosts
    assert "example.com" not in hosts


def test_extract_href_text_pairs():
    html = '<a href="http://evil.tld/">https://paypal.com/login</a>'
    pairs = extract_href_text_pairs(html)
    assert pairs == [("http://evil.tld/", "https://paypal.com/login")]


def test_find_domain_like_ignores_plain_text():
    assert find_domain_like("Click here") == ""


def test_find_domain_like_extracts_bare_and_schemed_domains():
    assert find_domain_like("paypal.com") == "paypal.com"
    assert find_domain_like("https://paypal.com/login") == "paypal.com"
