import pytest

from sigmalite.matchers import FieldMatcher, KeywordMatcher, MatcherError


def m(key, val, event):
    return FieldMatcher(key, val).matches(event)


def test_case_insensitive_equality_and_wildcard():
    assert m("User", "ADMIN", {"User": "admin"})
    assert m("File", "*.exe", {"File": "a.EXE"})
    assert not m("File", "*.exe", {"File": "a.exe.txt"})


def test_string_modifiers():
    e = {"c": r"C:\Windows\cmd.exe /c dir"}
    assert m("c|contains", "cmd.exe", e)
    assert m("c|startswith", "c:\\windows", e)
    assert m("c|endswith", "dir", e)
    assert not m("c|endswith", "cmd.exe", e)


def test_contains_all_vs_any():
    e = {"c": "procdump lsass"}
    assert m("c|contains|all", ["procdump", "lsass"], e)
    assert not m("c|contains|all", ["procdump", "mimikatz"], e)
    assert m("c|contains", ["procdump", "mimikatz"], e)


def test_nested_and_dotted_literal_keys():
    assert m("a.b", "x", {"a": {"b": "x"}})
    assert m("a.b", "x", {"a.b": "x"})


def test_regex_and_cidr_and_numeric():
    assert m("p|re", r"^\d{3}$", {"p": "443"})
    assert m("ip|cidr", "10.0.0.0/8", {"ip": "10.9.9.9"})
    assert not m("ip|cidr", "10.0.0.0/8", {"ip": "not-an-ip"})
    assert m("port|gte", 1024, {"port": 8080})
    assert not m("port|lt", 10, {"port": "abc"})


def test_exists_and_null():
    assert m("x|exists", True, {"x": 1})
    assert m("x|exists", False, {"y": 1})
    assert m("x", None, {"y": 1})
    assert not m("x", "a", {"y": 1})


def test_list_valued_field():
    assert m("tags", "evil", {"tags": ["ok", "EVIL"]})


def test_keywords_search_nested():
    assert KeywordMatcher(["mimikatz"]).matches({"a": {"b": ["run Mimikatz now"]}})
    assert not KeywordMatcher(["mimikatz"]).matches({"a": 1})


@pytest.mark.parametrize("key,val", [("f|bogus", "x"), ("f|re", "("), ("f|cidr", "zz"),
                                      ("f|gt", "abc"), ("f|exists", "yes"), ("f|re|contains", "x"),
                                      ("f", [])])
def test_invalid_definitions(key, val):
    with pytest.raises(MatcherError):
        FieldMatcher(key, val)
