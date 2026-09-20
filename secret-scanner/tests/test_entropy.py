from secret_scanner.entropy import find_high_entropy_assignments, is_placeholder, shannon_entropy


def test_shannon_entropy_of_empty_string_is_zero():
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_of_repeated_character_is_zero():
    assert shannon_entropy("aaaaaaaaaa") == 0.0


def test_shannon_entropy_of_varied_string_is_positive():
    assert shannon_entropy("aB3$xZ9!qL") > 2.5


def test_is_placeholder_detects_common_placeholders():
    assert is_placeholder("changeme")
    assert is_placeholder("REDACTED")
    assert is_placeholder("xxxxxxxxxxxx")
    assert is_placeholder("00000000")


def test_is_placeholder_false_for_real_looking_secret():
    assert not is_placeholder("Zx9kP2vQeT8mN4wLr7sYh1cBd6fJa3gQ")


def test_find_high_entropy_assignments_flags_secret_like_variable():
    text = 'api_key = "Zx9kP2vQeT8mN4wLr7sYh1cBd6fJa3gQ"\n'
    hits = list(find_high_entropy_assignments(text))
    assert len(hits) == 1
    key, value, _span, entropy = hits[0]
    assert key == "api_key"
    assert value == "Zx9kP2vQeT8mN4wLr7sYh1cBd6fJa3gQ"
    assert entropy > 0


def test_find_high_entropy_assignments_ignores_placeholder_values():
    text = 'api_key = "changeme"\n'
    assert list(find_high_entropy_assignments(text)) == []


def test_find_high_entropy_assignments_ignores_non_secret_variable_names():
    text = 'greeting = "ThisIsJustARegularGreetingNotASecretValue"\n'
    assert list(find_high_entropy_assignments(text)) == []


def test_find_high_entropy_assignments_ignores_short_values():
    text = 'api_key = "abc123"\n'
    assert list(find_high_entropy_assignments(text)) == []


def test_find_high_entropy_assignments_ignores_low_entropy_padding():
    text = 'password_field = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n'
    assert list(find_high_entropy_assignments(text)) == []
