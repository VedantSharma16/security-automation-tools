import pytest

from phishscope.domains import find_lookalike, registrable_domain


@pytest.mark.parametrize("host,expected", [
    ("www.paypal.com", "paypal.com"),
    ("a.b.example.co.uk", "example.co.uk"),
    ("localhost", "localhost"),
    ("185.234.219.17", "185.234.219.17"),
])
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


@pytest.mark.parametrize("domain,brand,technique", [
    ("paypa1.com", "paypal", "homoglyph"),
    ("rnicrosoft.com", "microsoft", "homoglyph"),
    ("micrsoft.com", "microsoft", "typosquat"),
    ("docusing.com", "docusign", "typosquat"),  # transposition
    ("paypal-account-verify.com", "paypal", "brand_embedding"),
    ("login.microsoft-support.net", "microsoft", "brand_embedding"),
    ("paypal.co", "paypal", "tld_swap"),
    ("xn--pypal-4ve.com", "paypal", "idn_homograph"),  # Cyrillic 'а'
])
def test_detects_lookalikes(domain, brand, technique):
    m = find_lookalike(domain)
    assert m is not None, domain
    assert (m.brand, m.technique) == (brand, technique)


@pytest.mark.parametrize("domain", [
    "paypal.com", "www.paypal.com", "login.microsoftonline.com", "github.com",
    "pineapple.com", "example.org", "chaisebank-unrelated.org", "applesauce-recipes.com",
])
def test_no_false_positive(domain):
    assert find_lookalike(domain) is None


def test_custom_brand_list():
    brands = {"corpbank": ["corpbank.com"]}
    assert find_lookalike("corpbank-secure.net", brands).brand == "corpbank"
    assert find_lookalike("paypa1.com", brands) is None


@pytest.mark.parametrize("domain", ["paypalsecure.com", "appleid-verify.net", "appleidverify.net"])
def test_brand_glued_to_lure_word(domain):
    m = find_lookalike(domain)
    assert m is not None and m.technique == "brand_embedding"
