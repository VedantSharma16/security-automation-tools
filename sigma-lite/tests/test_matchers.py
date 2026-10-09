import pytest

from sigmalite.matchers import MatcherError, match_field, split_field


def test_split_field():
    assert split_field("A|contains|all") == ("A", "contains", True)
    assert split_field("A") == ("A", None, False)


def test_unknown_modifier():
    with pytest.raises(MatcherError):
        split_field("A|base64")


def test_case_insensitive_equality_and_field_names():
    assert match_field({"User": "Admin"}, "user", "ADMIN")


def test_wildcards():
    assert match_field({"f": "C:\\x\\evil.exe"}, "f", "*\\evil.exe")
    assert not match_field({"f": "evil.exe.txt"}, "f", "*.exe")


def test_list_is_or_and_all_is_and():
    ev = {"c": "mimikatz sekurlsa"}
    assert match_field(ev, "c|contains", ["nope", "sekurlsa"])
    assert match_field(ev, "c|contains|all", ["mimikatz", "sekurlsa"])
    assert not match_field(ev, "c|contains|all", ["mimikatz", "nope"])


def test_regex_cidr_numeric():
    assert match_field({"c": "a1b22"}, "c|re", r"\d{2}")
    assert match_field({"ip": "10.2.3.4"}, "ip|cidr", "10.0.0.0/8")
    assert not match_field({"ip": "8.8.8.8"}, "ip|cidr", "10.0.0.0/8")
    assert match_field({"n": "10"}, "n|gt", 5)
    assert not match_field({"n": "abc"}, "n|gt", 5)


def test_missing_field_and_null():
    assert not match_field({}, "x", "a")
    assert match_field({}, "x", None)


def test_nested_dotted_path():
    assert match_field({"event": {"action": "x"}}, "event.action", "x")


def test_bad_regex():
    with pytest.raises(MatcherError):
        match_field({"a": "b"}, "a|re", "(")
