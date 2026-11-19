import pytest

from phishscope.domains import (
    damerau_levenshtein,
    decode_idna,
    find_lookalike,
    registrable_domain,
    skeleton,
)


@pytest.mark.parametrize("host,expected", [
    ("a.b.example.com", "example.com"),
    ("shop.amazon.co.uk", "amazon.co.uk"),
    ("example.com", "example.com"),
])
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


def test_damerau_levenshtein_counts_transposition_as_one():
    assert damerau_levenshtein("paypal", "papyal") == 1
    assert damerau_levenshtein("google", "gooogle") == 1
    assert damerau_levenshtein("abc", "abc") == 0


def test_skeleton_maps_confusables():
    assert skeleton("rnicr0soft") == skeleton("microsoft")
    assert skeleton("xn--pypal-4ve") == skeleton("paypal")  # Cyrillic 'а'


def test_decode_idna():
    assert decode_idna("xn--pypal-4ve.com") == "pаypal.com"


@pytest.mark.parametrize("host,technique", [
    ("paypa1.com", "homoglyph"),
    ("rnicrosoft.com", "homoglyph"),
    ("xn--pypal-4ve.com", "punycode"),
    ("gooogle.com", "typosquat"),
    ("paypal-secure-login.com", "brand-in-domain"),
    ("dhl-tracking.info", "brand-in-domain"),
    ("micros0ft-support.com", "homoglyph-brand-in-domain"),
])
def test_detects_lookalikes(host, technique):
    hit = find_lookalike(host)
    assert hit is not None and hit.technique == technique


@pytest.mark.parametrize("host", [
    "paypal.com", "www.paypal.com", "login.microsoftonline.com", "amazon.co.uk",
    "github.com", "pineapple.com", "applebees.com", "dl.dropboxusercontent.com", "",
])
def test_no_false_positives_on_legitimate_or_unrelated_domains(host):
    assert find_lookalike(host) is None


def test_protected_domains_extend_brand_list():
    assert find_lookalike("acme-c0rp.com") is None
    hit = find_lookalike("acme-c0rp.com", ["acme-corp.com"])
    assert hit and hit.imitates == "acme-corp.com"
    assert find_lookalike("mail.acme-corp.com", ["acme-corp.com"]) is None
