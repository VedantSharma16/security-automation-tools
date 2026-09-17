from phish_forensics.iocs import (
    assess_attachment_filename,
    defang_ip,
    defang_url,
    extract_ips,
    extract_urls,
    has_suspicious_tld,
    is_ip_literal_url,
    is_private_ip,
    is_shortener,
    url_domain,
)


def test_extract_urls_finds_http_and_www():
    text = "Visit https://example.com/path and also www.other.org for more."
    urls = extract_urls(text)
    assert "https://example.com/path" in urls
    assert any("www.other.org" in u for u in urls)


def test_extract_urls_dedupes_and_strips_trailing_punctuation():
    text = "See https://example.com/a. Also https://example.com/a, again."
    urls = extract_urls(text)
    assert urls.count("https://example.com/a") == 1


def test_extract_ips_filters_invalid_candidates():
    text = "Received from host (203.0.113.5) and bogus (999.999.999.999)"
    ips = extract_ips(text)
    assert ips == ["203.0.113.5"]


def test_defang_helpers():
    assert defang_url("http://evil.com/x") == "hxxp://evil[.]com/x"
    assert defang_ip("203.0.113.5") == "203[.]0[.]113[.]5"


def test_url_domain_and_ip_literal_detection():
    assert url_domain("https://example.com/path?q=1") == "example.com"
    assert is_ip_literal_url("http://203.0.113.5/login") is True
    assert is_ip_literal_url("https://example.com/login") is False


def test_shortener_and_suspicious_tld_detection():
    assert is_shortener("https://bit.ly/abc123") is True
    assert is_shortener("https://example.com/abc123") is False
    assert has_suspicious_tld("https://freegift.top/claim") is True
    assert has_suspicious_tld("https://example.com/claim") is False


def test_is_private_ip():
    assert is_private_ip("10.0.0.5") is True
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("8.8.8.8") is False


def test_dangerous_attachment_extension():
    risk = assess_attachment_filename("invoice.exe")
    assert risk.is_dangerous is True
    assert risk.is_double_extension is False


def test_double_extension_attachment():
    risk = assess_attachment_filename("invoice.pdf.exe")
    assert risk.is_dangerous is True
    assert risk.is_double_extension is True


def test_benign_attachment_extension():
    risk = assess_attachment_filename("quarterly_report.pdf")
    assert risk.is_dangerous is False
    assert risk.is_double_extension is False
