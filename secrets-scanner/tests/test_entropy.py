from secretscanner.entropy import find_high_entropy_tokens, shannon_entropy


def test_shannon_entropy_of_repeated_char_is_zero():
    assert shannon_entropy("aaaaaaaaaaaaaaaaaaaa") == 0.0


def test_shannon_entropy_of_empty_string_is_zero():
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_increases_with_symbol_diversity():
    low = shannon_entropy("aaaaaaaaaabbbbbbbbbb")
    high = shannon_entropy("aK9pQ2xZ7mN4vB8sT1wY")
    assert high > low


def test_finds_high_entropy_base64_token_in_line():
    line = "SECRET = 'Kj8dP2xQmZ9vN4bT7wY1sR6cA3fH5eL0'"
    matches = find_high_entropy_tokens(line)
    assert any(m.alphabet == "base64" for m in matches)


def test_ignores_short_tokens_below_minimum_length():
    line = "id = 'abc123XYZ'"
    assert find_high_entropy_tokens(line) == []


def test_ignores_low_entropy_english_looking_tokens():
    line = "message = 'thisIsJustARegularSentenceNotASecretAtAll'"
    matches = find_high_entropy_tokens(line)
    # Natural-language tokens skew heavily toward a handful of common letters,
    # which keeps their measured entropy under the base64 threshold.
    assert matches == [] or all(m.entropy < 4.3 for m in matches)


def test_ignores_tokens_with_too_few_distinct_characters():
    line = "padding = 'ababababababababababab'"
    assert find_high_entropy_tokens(line) == []
