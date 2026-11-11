import pytest

from phishtriage.checks import reference
from phishtriage.urls import (analyze_url, damerau_levenshtein, find_lookalike, normalize_host,
                              registrable_domain, skeleton)

BRANDS = {"PayPal": ["paypal.com"], "Microsoft": ["microsoft.com", "office.com"],
          "Apple": ["apple.com"], "Amazon": ["amazon.com", "amazon.co.uk"]}


def codes(href, text="", **kw):
    ref = reference()
    return {i.code for i in analyze_url(href, text, brands=kw.get("brands", BRANDS),
                                         shorteners=ref["shorteners"],
                                         suspicious_tlds=ref["suspicious_tlds"])}


@pytest.mark.parametrize("host,expected", [
    ("www.paypal.com", "paypal.com"),
    ("a.b.amazon.co.uk", "amazon.co.uk"),
    ("PAYPAL.COM.", "paypal.com"),
    ("10.0.0.1", "10.0.0.1"),
])
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


def test_normalize_decodes_punycode():
    assert normalize_host("xn--micrsoft-qbh.com") == "micrоsoft.com"


def test_skeleton_and_distance():
    assert skeleton("paypa1") == "paypal"
    assert skeleton("rnicrosoft") == "microsoft"
    assert skeleton("pаypal") == "paypal"  # Cyrillic а
    assert damerau_levenshtein("micorsoft", "microsoft") == 1  # transposition
    assert damerau_levenshtein("kitten", "sitting") == 3


@pytest.mark.parametrize("host,technique", [
    ("paypa1.com", "character substitution"),
    ("pаypal.com", "homoglyph"),
    ("micorsoft.com", "typosquat"),
    ("paypal-account-verify.com", "brand name in unrelated domain (combosquatting)"),
    ("paypal.com.secure-login.xyz", "brand name in unrelated domain (combosquatting)"),
    ("paypa1-secure.com", "character substitution + combosquatting"),
])
def test_lookalikes_detected(host, technique):
    assert find_lookalike(host, BRANDS)[1] == technique


@pytest.mark.parametrize("host", ["paypal.com", "www.paypal.com", "login.microsoftonline.office.com",
                                  "amazon.co.uk", "pineapple.com", "example.org", "203.0.113.5"])
def test_legitimate_or_unrelated_not_flagged(host):
    assert find_lookalike(host, BRANDS) is None


def test_url_indicators():
    assert "URL-IP" in codes("http://203.0.113.9/login")
    assert "URL-USERINFO" in codes("https://paypal.com@evil.example/x")
    assert "URL-SHORTENER" in codes("https://bit.ly/abc")
    assert "URL-TLD" in codes("https://free-prizes.xyz/")
    assert "URL-PUNYCODE" in codes("https://xn--micrsoft-qbh.com/")
    assert {"URL-LOOKALIKE", "URL-CRED-PATH"} <= codes("https://paypa1.com/signin")
    assert "URL-SCHEME" in codes("javascript:alert(1)")
    assert "URL-DEEP-SUBDOMAIN" in codes("https://a.b.c.d.example.com/")


def test_display_text_mismatch():
    assert "URL-MISMATCH" in codes("https://evil.example/", "https://www.paypal.com/")
    assert "URL-MISMATCH" not in codes("https://www.paypal.com/x", "paypal.com")
    assert "URL-MISMATCH" not in codes("https://evil.example/", "Click here to log in")


def test_ignored_schemes():
    assert codes("mailto:a@b.com") == set()
    assert codes("#top") == set()
