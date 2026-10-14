import pytest
from sigmalite.matchers import FieldMatcher, ModifierError, Selection, get_field


def m(key, val, ev):
    return FieldMatcher(key, val).matches(ev)


def test_exact_is_case_insensitive():
    assert m("User", "Admin", {"User": "aDMIN"})
    assert not m("User", "admin", {"User": "administrator"})


def test_contains_startswith_endswith():
    ev = {"c": r"C:\Windows\cmd.exe /c calc"}
    assert m("c|contains", "calc", ev)
    assert m("c|startswith", "c:\\windows", ev)
    assert not m("c|endswith", "cmd.exe", ev)


def test_wildcards():
    assert m("f", "ab*z", {"f": "abXXz"})
    assert m("f", "a?c", {"f": "abc"})
    assert not m("f", "a?c", {"f": "abbc"})


def test_all_modifier_requires_every_value():
    assert m("c|contains|all", ["a", "b"], {"c": "ab"})
    assert not m("c|contains|all", ["a", "z"], {"c": "ab"})


def test_list_values_are_or():
    assert m("c|contains", ["x", "b"], {"c": "abc"})


def test_regex_and_bad_regex():
    assert m("c|re", r"^\d{3}$", {"c": "123"})
    with pytest.raises(ModifierError):
        FieldMatcher("c|re", "(")


def test_cidr():
    assert m("ip|cidr", "10.0.0.0/8", {"ip": "10.9.9.9"})
    assert not m("ip|cidr", "10.0.0.0/8", {"ip": "11.0.0.1"})
    assert not m("ip|cidr", "10.0.0.0/8", {"ip": "not-an-ip"})


def test_numeric_comparison():
    assert m("n|gte", 10, {"n": "10"})
    assert not m("n|lt", 10, {"n": "abc"})


def test_null_matches_missing():
    assert m("x", None, {"y": 1})
    assert not m("x", None, {"x": "v"})


def test_unknown_modifier_rejected():
    with pytest.raises(ModifierError):
        FieldMatcher("a|bogus", "x")


def test_field_lookup_case_insensitive_and_nested():
    assert get_field({"Image": 1}, "image") == 1
    assert get_field({"a": {"b": 5}}, "a.b") == 5
    assert get_field({"a": 1}, "a.b") is None


def test_selection_list_of_maps_is_or_and_map_is_and():
    sel = Selection([{"a": 1, "b": 2}, {"c": 3}])
    assert sel.matches({"a": 1, "b": 2})
    assert not sel.matches({"a": 1})
    assert sel.matches({"c": 3})
