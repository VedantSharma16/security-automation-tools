from phish_forensics.lookalike import (
    brands_mentioned_in,
    check_domain_against_brands,
)


def test_official_domain_is_not_flagged():
    assert check_domain_against_brands("paypal.com") == []


def test_legitimate_subdomain_is_not_flagged():
    assert check_domain_against_brands("mail.google.com") == []


def test_substring_typosquat_is_flagged():
    matches = check_domain_against_brands("paypal-secure-login.com")
    assert any(m.brand == "paypal" and m.technique == "substring" for m in matches)


def test_edit_distance_typosquat_is_flagged():
    matches = check_domain_against_brands("paypaI.com")  # capital i substituted, still edit-distance 1 as lowercase 'i'
    assert any(m.brand == "paypal" for m in matches)


def test_leetspeak_homoglyph_typosquat_is_flagged():
    matches = check_domain_against_brands("micr0soft.com")
    assert any(m.brand == "microsoft" and m.technique in ("homoglyph", "edit-distance") for m in matches)


def test_unrelated_domain_is_not_flagged():
    assert check_domain_against_brands("my-personal-blog.dev") == []


def test_brands_mentioned_in_display_name():
    assert "paypal" in brands_mentioned_in("PayPal Security Team")
    assert brands_mentioned_in("Just a regular person") == []


def test_brand_word_boundary_avoids_false_positive_substring():
    # "upsstream" should not match the "ups" brand as a whole word
    assert "ups" not in brands_mentioned_in("upsstream analytics report")
