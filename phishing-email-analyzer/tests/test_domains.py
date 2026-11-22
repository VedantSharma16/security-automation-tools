import pytest

from phishtriage.domains import (
    damerau_levenshtein,
    find_lookalike,
    registrable_domain,
    skeleton,
)


@pytest.mark.parametrize("host,technique,brand", [
    ("paypa1.com", "homoglyph", "PayPal"),
    ("rnicrosoft.com", "homoglyph", "Microsoft"),
    ("xn--pypal-4ve.com", "homoglyph", "PayPal"),          # Cyrillic 'а'
    ("gooogle.com", "typosquat", "Google"),
    ("paypal-secure-login.com", "combosquat", "PayPal"),
    ("paypal.com.account-verify.xyz", "subdomain-spoof", "PayPal"),
])
def test_detects_lookalikes(host, technique, brand):
    match = find_lookalike(host)
    assert match is not None
    assert (match.technique, match.brand) == (technique, brand)


@pytest.mark.parametrize("host", [
    "paypal.com", "www.paypal.com", "login.microsoftonline.com", "github.com",
    "example.com", "10.0.0.1", "",
])
def test_legitimate_and_unrelated_domains_are_not_flagged(host):
    assert find_lookalike(host) is None


def test_registrable_domain_handles_multi_label_suffixes():
    assert registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert registrable_domain("mail.commbank.com.au") == "commbank.com.au"
    assert registrable_domain("x.y.example.com") == "example.com"


def test_skeleton_and_distance():
    assert skeleton("paypa1") == skeleton("paypal")
    assert damerau_levenshtein("google", "gogole") == 1  # transposition
    assert damerau_levenshtein("abc", "abc") == 0
