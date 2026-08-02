from secretscan.entropy import (
    find_entropy_secrets,
    looks_like_placeholder,
    shannon_entropy,
)


def test_shannon_entropy_empty_string_is_zero():
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_repeated_char_is_zero():
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_shannon_entropy_random_string_is_high():
    assert shannon_entropy("Tg5$kP9!zQ2@wR7#") > 3.5


def test_looks_like_placeholder_matches_common_placeholders():
    assert looks_like_placeholder("changeme")
    assert looks_like_placeholder("CHANGE_ME")
    assert looks_like_placeholder("<your-api-key-here>")
    assert looks_like_placeholder("${SECRET_TOKEN}")
    assert looks_like_placeholder("xxxxxxxxxxxxxxxx")


def test_looks_like_placeholder_rejects_real_looking_secret():
    assert not looks_like_placeholder("Tg5kP9zQ2wR7mN3xL8vB1cH6")


def test_looks_like_placeholder_low_diversity_string():
    assert looks_like_placeholder("abababababababab")


def test_find_entropy_secrets_flags_suspicious_key_high_entropy_value():
    line = 'api_key = "Tg5kP9zQ2wR7mN3xL8vB1cH6yF4d"'
    matches = find_entropy_secrets(line)
    assert len(matches) == 1
    assert matches[0].key == "api_key"


def test_find_entropy_secrets_ignores_non_secret_key_names():
    line = 'description = "Tg5kP9zQ2wR7mN3xL8vB1cH6yF4d"'
    assert find_entropy_secrets(line) == []


def test_find_entropy_secrets_ignores_placeholder_values():
    line = 'password = "changeme"'
    assert find_entropy_secrets(line) == []


def test_find_entropy_secrets_ignores_low_entropy_values():
    line = 'secret_token = "aaaaaaaaaaaaaaaa"'
    assert find_entropy_secrets(line) == []


def test_find_entropy_secrets_ignores_short_values():
    line = 'password = "short1"'
    assert find_entropy_secrets(line) == []


def test_find_entropy_secrets_respects_min_length_and_entropy_overrides():
    line = 'token = "abc123xy"'
    assert find_entropy_secrets(line, min_length=4, min_entropy=0.0) != []
    assert find_entropy_secrets(line, min_length=100) == []
