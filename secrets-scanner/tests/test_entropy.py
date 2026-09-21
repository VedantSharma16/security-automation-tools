from secretscan.entropy import is_high_entropy, looks_like_placeholder, shannon_entropy


def test_shannon_entropy_of_empty_string_is_zero():
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_of_repeated_char_is_zero():
    assert shannon_entropy("aaaaaaaaaa") == 0.0


def test_shannon_entropy_of_random_string_is_high():
    assert shannon_entropy("wJalrXUtnFEMI9K7MDENGbPxRfiCYzt7B4wLpqRJ") > 4.0


def test_looks_like_placeholder_flags_common_markers():
    assert looks_like_placeholder("changeme")
    assert looks_like_placeholder("your_api_key_here")
    assert looks_like_placeholder("xxxxxxxx")
    assert looks_like_placeholder("<redacted>")
    assert looks_like_placeholder("aaaaaaaa")


def test_looks_like_placeholder_allows_real_looking_secrets():
    assert not looks_like_placeholder("wJalrXUtnFEMI9K7MDENGbPxRfiCYzt7B4wLpqRJ")


def test_is_high_entropy_requires_min_length():
    assert not is_high_entropy("aB3$xZ9!", min_length=16)


def test_is_high_entropy_rejects_placeholder_even_if_long_enough():
    assert not is_high_entropy("changeme_changeme_changeme_1234", min_length=16)


def test_is_high_entropy_accepts_real_secret():
    assert is_high_entropy("wJalrXUtnFEMI9K7MDENGbPxRfiCYzt7B4wLpqRJ")
