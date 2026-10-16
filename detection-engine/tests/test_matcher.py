import pytest

from sigmalite.matcher import FieldMatcher, MatchError, Selection, get_field


def m(key, val, event):
    return FieldMatcher(key, val).matches(event)


def test_equals_case_insensitive_and_wildcard():
    assert m("a", "HELLO", {"a": "hello"})
    assert m("a", "he*o", {"a": "Hello"})
    assert not m("a", "he*o", {"a": "hellox"})


def test_contains_any_vs_all():
    ev = {"c": "procdump -ma lsass"}
    assert m("c|contains", ["lsass", "nope"], ev)
    assert not m("c|contains|all", ["lsass", "nope"], ev)
    assert m("c|contains|all", ["lsass", "-ma"], ev)


def test_startswith_endswith_regex():
    ev = {"p": r"C:\x\evil.exe"}
    assert m("p|endswith", ".exe", ev)
    assert m("p|startswith", "c:\\x", ev)
    assert m("p|re", r"ev[il]+\.exe$", ev)


def test_cidr_and_numeric():
    assert m("ip|cidr", "10.0.0.0/8", {"ip": "10.2.3.4"})
    assert not m("ip|cidr", "10.0.0.0/8", {"ip": "8.8.8.8"})
    assert not m("ip|cidr", "10.0.0.0/8", {"ip": "not-an-ip"})
    assert m("port|gte", 1024, {"port": "4444"})
    assert not m("port|lt", 10, {"port": "abc"})


def test_missing_field_and_null():
    assert not m("x|contains", "a", {})
    assert m("x", None, {})


def test_dotted_and_case_insensitive_field():
    assert get_field({"Process": {"Name": "a"}}, "process.name") == "a"


def test_bad_modifiers_rejected():
    for key in ("a|bogus", "a|contains|re", "|contains"):
        with pytest.raises(MatchError):
            FieldMatcher(key, "x")
    with pytest.raises(MatchError):
        FieldMatcher("a|re", "([")


def test_selection_list_is_or_of_groups():
    s = Selection([{"a": "1"}, {"b": "2"}])
    assert s.matches({"b": "2"})
    assert not s.matches({"a": "2"})
