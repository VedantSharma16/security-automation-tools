import pytest

from phishlens.domains import (
    damerau_levenshtein,
    decode_idn,
    find_lookalike,
    hostname,
    is_ip,
    registrable_domain,
    skeleton,
)

PROTECTED = ["paypal.com", "microsoft.com", "microsoftonline.com", "amazon.com", "github.com", "dhl.com"]


@pytest.mark.parametrize("url,host", [
    ("https://Login.Example.COM/path?q=1", "login.example.com"),
    ("www.example.org/abc", "www.example.org"),
    ("//cdn.example.net/x.js", "cdn.example.net"),
    ("http://user@evil.example/", "evil.example"),
    ("http://198.51.100.4:8080/", "198.51.100.4"),
])
def test_hostname(url, host):
    assert hostname(url) == host


@pytest.mark.parametrize("host,reg", [
    ("a.b.example.com", "example.com"),
    ("mail.bbc.co.uk", "bbc.co.uk"),
    ("example.com", "example.com"),
    ("203.0.113.9", "203.0.113.9"),
])
def test_registrable_domain(host, reg):
    assert registrable_domain(host) == reg


def test_is_ip():
    assert is_ip("10.0.0.1") and is_ip("::1") and not is_ip("example.com")


def test_skeleton_folds_homoglyphs():
    assert skeleton("paypa1") == skeleton("paypal")
    assert skeleton("rnicrosoft") == skeleton("microsoft")
    assert skeleton("g00gle") == skeleton("google")
    assert skeleton("pаypal") == skeleton("paypal")  # Cyrillic 'а'


def test_damerau_levenshtein_transposition():
    assert damerau_levenshtein("amazon", "amzaon") == 1
    assert damerau_levenshtein("kitten", "sitting") == 3
    assert damerau_levenshtein("same", "same") == 0


def test_decode_idn():
    assert decode_idn("xn--micrsoft-qbh.com") == "micrоsoft.com"
    assert decode_idn("example.com") == "example.com"


@pytest.mark.parametrize("host,impersonates,technique", [
    ("paypa1.com", "paypal.com", "homoglyph"),
    ("rnicrosoft.com", "microsoft.com", "homoglyph"),
    ("xn--micrsoft-qbh.com", "microsoft.com", "idn_homograph"),
    ("amazom.com", "amazon.com", "typosquat"),
    ("paypal.co", "paypal.com", "typosquat"),
    ("paypal-verify.com", "paypal.com", "combosquat"),
    ("secure.paypa1-security.com", "paypal.com", "combosquat"),
    ("login.microsoftonline.com.auth-session.top", "microsoftonline.com", "brand_in_subdomain"),
])
def test_find_lookalike_detects(host, impersonates, technique):
    m = find_lookalike(host, PROTECTED)
    assert m is not None, host
    assert m.impersonates == impersonates
    assert m.technique == technique


@pytest.mark.parametrize("host", [
    "paypal.com",
    "www.paypal.com",
    "login.microsoftonline.com",
    "github.com",
    "dhi.com",             # short protected labels (dhl) are deliberately skipped
    "example.org",
    "203.0.113.5",
    "",
])
def test_find_lookalike_ignores_legit_and_unrelated(host):
    assert find_lookalike(host, PROTECTED) is None
