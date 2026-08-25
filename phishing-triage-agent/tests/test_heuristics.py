from phishing_agent import heuristics

TRUSTED = {"paypal.com": "PayPal", "apple.com": "Apple"}


def test_levenshtein_basic_cases():
    assert heuristics.levenshtein("a", "a") == 0
    assert heuristics.levenshtein("", "abc") == 3
    assert heuristics.levenshtein("kitten", "sitting") == 3


def test_domain_of_handles_urls_and_addresses():
    assert heuristics.domain_of("https://Evil.Example.com/path") == "evil.example.com"
    assert heuristics.domain_of("user@Example.COM") == "example.com"
    assert heuristics.domain_of("https://host.com:8443/x") == "host.com"


def test_is_ip_literal():
    assert heuristics.is_ip_literal("192.168.1.10") is True
    assert heuristics.is_ip_literal("example.com") is False


def test_is_punycode():
    assert heuristics.is_punycode("xn--pypal-4ve.com") is True
    assert heuristics.is_punycode("paypal.com") is False


def test_closest_trusted_brand_flags_near_miss_not_exact_match():
    result = heuristics.closest_trusted_brand("paypa1.com", TRUSTED)
    assert result is not None
    brand_domain, brand_name, distance = result
    assert brand_domain == "paypal.com"
    assert brand_name == "PayPal"
    assert distance == 1

    # An exact match is not a typosquat.
    assert heuristics.closest_trusted_brand("paypal.com", TRUSTED) is None
    # Something unrelated shouldn't match either.
    assert heuristics.closest_trusted_brand("totally-unrelated-domain.io", TRUSTED) is None


def test_display_name_mismatch_detects_impersonation():
    brand = heuristics.display_name_mismatch("PayPal Security", "alerts@paypa1-secure.com", TRUSTED)
    assert brand == "PayPal"

    assert heuristics.display_name_mismatch("PayPal Security", "alerts@paypal.com", TRUSTED) is None
    assert heuristics.display_name_mismatch("Priya Natarajan", "priya@example-corp.com", TRUSTED) is None


def test_urgency_language_hits():
    text = "Your account has been suspended. Verify your account immediately."
    hits = heuristics.urgency_language_hits(text)
    assert "your account has been suspended" in hits
    assert "verify your account" in hits
    assert heuristics.urgency_language_hits("Here are the notes from standup.") == []


def test_risky_attachment_flags():
    assert heuristics.risky_attachment_flags("invoice.pdf") == []
    assert "risky_extension" in heuristics.risky_attachment_flags("payload.exe")
    flags = heuristics.risky_attachment_flags("account_statement.pdf.exe")
    assert "risky_extension" in flags
    assert "double_extension" in flags
