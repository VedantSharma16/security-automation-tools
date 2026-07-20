from secretscanner.entropy import is_high_entropy_secret, is_placeholder, shannon_entropy


def test_shannon_entropy_of_empty_string_is_zero():
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_of_repeated_char_is_zero():
    assert shannon_entropy("aaaaaaaaaa") == 0.0


def test_shannon_entropy_of_random_looking_string_is_high():
    assert shannon_entropy("aK9$xQ2!pL7&mZ4^vR1@") > 3.5


def test_is_placeholder_catches_common_dummy_words():
    assert is_placeholder("your_api_key_here")
    assert is_placeholder("CHANGEME_IN_PRODUCTION")
    assert is_placeholder("example-secret-value")
    assert is_placeholder("<INSERT_SECRET_HERE>")


def test_is_placeholder_catches_low_distinct_char_strings():
    assert is_placeholder("00000000000000000000")
    assert is_placeholder("abababababababababab")


def test_is_placeholder_false_for_random_string():
    assert not is_placeholder("aK9xQ2pL7mZ4vR1wT8yU3")


def test_is_high_entropy_secret_true_for_random_token():
    assert is_high_entropy_secret("aK9xQ2pL7mZ4vR1wT8yU3jH6")


def test_is_high_entropy_secret_false_for_short_value():
    assert not is_high_entropy_secret("aK9xQ2pL")


def test_is_high_entropy_secret_false_for_placeholder():
    assert not is_high_entropy_secret("your_api_key_here_please_replace")


def test_is_high_entropy_secret_false_for_low_entropy_long_string():
    assert not is_high_entropy_secret("aaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbb")
