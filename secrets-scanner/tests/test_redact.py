from secretscan.redact import redact


def test_redact_keeps_first_and_last_four_chars():
    assert redact("AKIAIOSFODNN7EXAMPLE") == "AKIA...MPLE"


def test_redact_fully_masks_short_values():
    assert redact("short") == "*****"


def test_redact_never_contains_the_middle_of_a_long_secret():
    secret = "wJalrXUtnFEMI9K7MDENGbPxRfiCYzt7B4wLpqRJ"
    out = redact(secret)
    assert secret[6:-6] not in out
