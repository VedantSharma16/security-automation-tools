from secret_sentinel.entropy import (
    find_candidate_assignments,
    is_high_entropy_secret,
    is_placeholder,
    shannon_entropy,
)


def test_shannon_entropy_empty_string_is_zero():
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_single_repeated_char_is_zero():
    assert shannon_entropy("aaaaaaaaaaaa") == 0.0


def test_shannon_entropy_all_unique_chars_is_log2_of_length():
    import math

    value = "Xk29LpQzT8mNc4Rb"  # 16 distinct characters
    assert math.isclose(shannon_entropy(value), 4.0, rel_tol=1e-9)


def test_is_placeholder_matches_common_placeholders():
    for value in ["changeme", "CHANGE_ME", "your-api-key-here", "example", "xxxxxxxx", "0000000000"]:
        assert is_placeholder(value), value


def test_is_placeholder_rejects_real_looking_value():
    assert not is_placeholder("Xk29LpQzT8mNc4Rb")


def test_is_high_entropy_secret_true_for_random_looking_value():
    assert is_high_entropy_secret("Xk29LpQzT8mNc4Rb")


def test_is_high_entropy_secret_false_for_short_value():
    assert not is_high_entropy_secret("Xk29Lp")


def test_is_high_entropy_secret_false_for_low_entropy_repetitive_value():
    assert not is_high_entropy_secret("abababababab")


def test_is_high_entropy_secret_false_for_placeholder_even_if_long():
    assert not is_high_entropy_secret("your-secret-api-key-here")


def test_find_candidate_assignments_matches_prefixed_and_suffixed_names():
    line = 'db_password = "Xk29LpQzT8mNc4Rb"'
    assert find_candidate_assignments(line) == [("db_password", "Xk29LpQzT8mNc4Rb")]

    line2 = 'stripe_secret_key: "Xk29LpQzT8mNc4Rb"'
    assert find_candidate_assignments(line2) == [("stripe_secret_key", "Xk29LpQzT8mNc4Rb")]


def test_find_candidate_assignments_ignores_unrelated_variable_names():
    # Well-formed assignment, but "timeout" isn't a secret-shaped name.
    line = 'timeout_value = "Xk29LpQzT8mNc4Rb"'
    assert find_candidate_assignments(line) == []


def test_find_candidate_assignments_requires_secret_keyword_substring():
    # "monkey" contains "key" as a substring -- a known, documented tradeoff:
    # substring matching on variable names catches more real secrets at the
    # cost of occasionally considering unrelated names as candidates. The
    # entropy check downstream is what keeps this precise in practice.
    line = 'monkey_name = "just_a_regular_value"'
    assert find_candidate_assignments(line) == [("monkey_name", "just_a_regular_value")]
