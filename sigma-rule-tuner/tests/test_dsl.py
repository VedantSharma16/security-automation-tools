import pytest

from sigma_tuner.dsl import ConditionError, evaluate_block, evaluate_condition, evaluate_field, evaluate_rule


class TestEvaluateField:
    def test_plain_equality_case_insensitive(self):
        assert evaluate_field({"process_name": "Mimikatz.EXE"}, "process_name", "mimikatz.exe")

    def test_plain_equality_list_is_or(self):
        assert evaluate_field({"process_name": "mimikatz.exe"}, "process_name", ["procdump.exe", "mimikatz.exe"])
        assert not evaluate_field({"process_name": "notepad.exe"}, "process_name", ["procdump.exe", "mimikatz.exe"])

    def test_missing_field_never_matches(self):
        assert not evaluate_field({}, "process_name", "mimikatz.exe")
        assert not evaluate_field({"process_name": None}, "process_name", "mimikatz.exe")

    @pytest.mark.parametrize(
        "modifier,value,candidate,expected",
        [
            ("contains", "rundll32.exe comsvcs.dll MiniDump", "comsvcs.dll", True),
            ("contains", "notepad.exe", "comsvcs.dll", False),
            ("startswith", "10.0.0.5", "10.", True),
            ("startswith", "203.0.113.10", "10.", False),
            ("endswith", "lsass.dmp", ".dmp", True),
        ],
    )
    def test_string_modifiers(self, modifier, value, candidate, expected):
        assert evaluate_field({"f": value}, f"f|{modifier}", candidate) is expected

    def test_string_modifier_non_string_field_is_no_match(self):
        assert not evaluate_field({"f": 5}, "f|contains", "5")

    def test_regex_modifier(self):
        assert evaluate_field({"cmd": "powershell.exe -enc SQBFAFgA"}, "cmd|re", r"-enc\s+[A-Za-z0-9+/=]+")
        assert not evaluate_field({"cmd": "notepad.exe"}, "cmd|re", r"-enc\s+[A-Za-z0-9+/=]+")

    @pytest.mark.parametrize(
        "modifier,value,threshold,expected",
        [
            ("gte", 5, 5, True),
            ("gte", 4, 5, False),
            ("lte", 5, 5, True),
            ("lte", 6, 5, False),
            ("gt", 6, 5, True),
            ("gt", 5, 5, False),
            ("lt", 4, 5, True),
        ],
    )
    def test_numeric_modifiers(self, modifier, value, threshold, expected):
        assert evaluate_field({"n": value}, f"n|{modifier}", threshold) is expected

    def test_numeric_modifier_non_numeric_field_is_no_match(self):
        assert not evaluate_field({"n": "not-a-number"}, "n|gte", 5)

    def test_unknown_modifier_raises(self):
        with pytest.raises(ValueError):
            evaluate_field({"f": "x"}, "f|bogus", "x")


class TestEvaluateBlock:
    def test_block_is_and_of_fields(self):
        block = {"event_type": "auth_failure", "failed_attempts_5m|gte": 5}
        assert evaluate_block({"event_type": "auth_failure", "failed_attempts_5m": 5}, block)
        assert not evaluate_block({"event_type": "auth_failure", "failed_attempts_5m": 4}, block)
        assert not evaluate_block({"event_type": "auth_success", "failed_attempts_5m": 5}, block)

    def test_empty_block_matches_everything(self):
        assert evaluate_block({"anything": "goes"}, {})


class TestEvaluateCondition:
    def test_and_or_not(self):
        results = {"selection": True, "filter": False}
        assert evaluate_condition("selection and not filter", results)
        assert evaluate_condition("selection or filter", results)
        assert not evaluate_condition("filter", results)

    def test_parentheses(self):
        results = {"a": True, "b": False, "c": False}
        assert evaluate_condition("a and (b or c)", results) is False
        assert evaluate_condition("(a or b) and not c", results) is True

    def test_unknown_block_raises(self):
        with pytest.raises(ConditionError):
            evaluate_condition("selection and mystery", {"selection": True})

    def test_syntax_error_raises(self):
        with pytest.raises(ConditionError):
            evaluate_condition("selection and (", {"selection": True})

    def test_cannot_execute_arbitrary_code(self):
        # A condition string is never eval()'d directly -- calls, attribute
        # access, and comparisons are all outside the allowed AST node set.
        with pytest.raises(ConditionError):
            evaluate_condition("__import__('os').system('echo pwned')", {})
        with pytest.raises(ConditionError):
            evaluate_condition("selection == True", {"selection": True})


class TestEvaluateRule:
    def test_full_rule(self):
        rule = {
            "detection": {
                "selection": {"event_type": "auth_failure", "failed_attempts_5m|gte": 5},
                "filter": {"src_ip|startswith": ["10.", "192.168."]},
                "condition": "selection and not filter",
            }
        }
        assert evaluate_rule(rule, {"event_type": "auth_failure", "failed_attempts_5m": 6, "src_ip": "203.0.113.10"})
        assert not evaluate_rule(rule, {"event_type": "auth_failure", "failed_attempts_5m": 6, "src_ip": "10.0.0.5"})
        assert not evaluate_rule(rule, {"event_type": "auth_failure", "failed_attempts_5m": 1, "src_ip": "203.0.113.10"})
