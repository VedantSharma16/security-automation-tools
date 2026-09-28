from phishtriage.headers import (
    display_name_impersonation,
    domain_of,
    parse_auth_results,
    reply_to_mismatch,
    return_path_mismatch,
)


def test_parse_auth_results_extracts_all_three():
    raw = "mx.example.com; spf=fail smtp.mailfrom=x.com; dkim=none; dmarc=fail (p=reject)"
    results = parse_auth_results(raw)
    assert results.spf == "fail"
    assert results.dkim == "none"
    assert results.dmarc == "fail"
    assert results.any_failed() is True
    assert results.none_present() is False


def test_parse_auth_results_handles_missing_header():
    results = parse_auth_results("")
    assert results.none_present() is True
    assert results.any_failed() is False


def test_parse_auth_results_all_pass():
    raw = "mx.example.com; spf=pass; dkim=pass header.d=example.com; dmarc=pass"
    results = parse_auth_results(raw)
    assert results.any_failed() is False


def test_domain_of():
    assert domain_of("user@Example.COM") == "example.com"
    assert domain_of("") == ""
    assert domain_of("not-an-email") == ""


def test_display_name_impersonation_detects_spoof():
    brand = display_name_impersonation("PayPal Support", "security@paypa1-verify.com")
    assert brand == "paypal.com"


def test_display_name_impersonation_allows_real_sender():
    brand = display_name_impersonation("PayPal Support", "security@paypal.com")
    assert brand is None


def test_display_name_impersonation_allows_subdomain():
    brand = display_name_impersonation("PayPal Support", "security@mail.paypal.com")
    assert brand is None


def test_display_name_impersonation_none_when_no_brand_mentioned():
    assert display_name_impersonation("Alex Smith", "alex@example.com") is None


def test_reply_to_mismatch():
    assert reply_to_mismatch("a@example.com", "b@other.com") is True
    assert reply_to_mismatch("a@example.com", "b@example.com") is False
    assert reply_to_mismatch("a@example.com", "") is False


def test_return_path_mismatch_flags_near_miss_domain():
    assert return_path_mismatch("security@paypa1-verify.com", "bounce@paypa1-verify.com") is False
    assert return_path_mismatch("security@paypal.com", "bounce@paypa1.com") is True


def test_return_path_mismatch_allows_unrelated_esp_domain():
    # Legitimate bulk-mail platforms commonly use an unrelated Return-Path
    # domain; only a *close* variant of the From domain should be flagged.
    assert return_path_mismatch("news@example.com", "bounce@mailplatform.io") is False
