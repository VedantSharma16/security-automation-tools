import pytest

from codesec.entropy import looks_like_secret, shannon_entropy


def test_shannon_entropy_empty_string():
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_repeated_char_is_zero():
    assert shannon_entropy("aaaaaaaaaa") == 0.0


def test_shannon_entropy_higher_for_random_looking_string():
    assert shannon_entropy("aB3$kZ9!qP2#") > shannon_entropy("aaaaaaaaaaaa")


def test_looks_like_secret_rejects_short_strings():
    assert not looks_like_secret("Ab3$Zq9!")


def test_looks_like_secret_rejects_known_placeholders():
    assert not looks_like_secret("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")


def test_looks_like_secret_accepts_high_entropy_token():
    assert looks_like_secret("qzR8vN2mLwK6xC4tY1jH5pB9dF3sA7g")


def test_looks_like_secret_rejects_low_entropy_hex_id():
    # A plausible git-commit-like hex string is high-cardinality-looking but
    # low entropy relative to the stricter hex bar.
    assert not looks_like_secret("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")


@pytest.mark.parametrize("min_length", [10, 30])
def test_looks_like_secret_respects_min_length(min_length):
    token = "Ab3$kZ9!qP2#Lm8"
    assert looks_like_secret(token, min_length=min_length) == (len(token) >= min_length)
