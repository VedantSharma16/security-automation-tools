from secretscan.entropy import find_high_entropy_assignments, shannon_entropy


class TestShannonEntropy:
    def test_empty_string_is_zero(self):
        assert shannon_entropy("") == 0.0

    def test_repeated_character_is_zero(self):
        assert shannon_entropy("aaaaaaaaaa") == 0.0

    def test_random_looking_string_has_high_entropy(self):
        assert shannon_entropy("aZ9$kQ2!mP7&vR4#") > 3.5

    def test_two_char_alternation_has_low_entropy(self):
        assert shannon_entropy("abababababab") < 1.5


class TestFindHighEntropyAssignments:
    def test_flags_suspicious_name_with_random_value(self):
        line = 'internal_service_token = "9fA2xQ7mZ0pL5vC8rT1yW3nB6hK4eD9gU2i"'
        found = find_high_entropy_assignments(line)
        assert len(found) == 1
        assert found[0].variable_name == "internal_service_token"

    def test_ignores_non_suspicious_variable_names(self):
        line = 'description = "this is just a long descriptive string of prose"'
        assert find_high_entropy_assignments(line) == []

    def test_ignores_short_values(self):
        line = 'auth_token = "short"'
        assert find_high_entropy_assignments(line) == []

    def test_ignores_placeholder_values(self):
        line = 'api_secret = "your_actual_secret_key_value_here"'
        assert find_high_entropy_assignments(line) == []

    def test_ignores_single_char_class_dictionary_phrases(self):
        # High Shannon entropy, but only one character class (lowercase) --
        # real generated secrets almost always mix classes; plain words don't.
        line = 'password = "correcthorsebatterystaple"'
        assert find_high_entropy_assignments(line) == []

    def test_ignores_low_entropy_words(self):
        line = 'session_id = "thequickbrownfoxjumpsoverthelazydog"'
        assert find_high_entropy_assignments(line) == []

    def test_respects_custom_min_length(self):
        # 35 chars: qualifies under the default MIN_LENGTH (20) but not a
        # stricter caller-supplied threshold.
        line = 'token = "9fA2xQ7mZ0pL5vC8rT1yW3nB6hK4eD9gU2i"'
        assert find_high_entropy_assignments(line) != []
        assert find_high_entropy_assignments(line, min_length=50) == []
