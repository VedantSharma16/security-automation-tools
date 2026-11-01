import pytest
from sigmalite.matcher import _match_field, _match_selection


def test_case_insensitive_equality():
    assert _match_field({"A": "Foo"}, "A", "fOO")


def test_modifiers():
    e = {"c": r"C:\Windows\cmd.exe /C whoami"}
    assert _match_field(e, "c|contains", "WHOAMI")
    assert _match_field(e, "c|startswith", "c:\\windows")
    assert _match_field(e, "c|endswith", "whoami")
    assert _match_field(e, "c|re", r"cmd\.exe\s+/c")
    assert not _match_field(e, "c|contains", "powershell")


def test_all_modifier_requires_every_value():
    e = {"c": "a b"}
    assert _match_field(e, "c|contains|all", ["a", "b"])
    assert not _match_field(e, "c|contains|all", ["a", "z"])
    assert _match_field(e, "c|contains", ["z", "b"])


def test_cidr_and_numeric():
    assert _match_field({"ip": "10.2.3.4"}, "ip|cidr", "10.0.0.0/8")
    assert not _match_field({"ip": "8.8.8.8"}, "ip|cidr", "10.0.0.0/8")
    assert not _match_field({"ip": "garbage"}, "ip|cidr", "10.0.0.0/8")
    assert _match_field({"n": 5}, "n|gt", 3)
    assert not _match_field({"n": "x"}, "n|gt", 3)


def test_nested_and_missing_fields():
    assert _match_field({"a": {"b": "x"}}, "a.b", "x")
    assert not _match_field({}, "a.b", "x")
    assert _match_field({}, "a", None)


def test_wildcard_equality():
    assert _match_field({"f": "report.docx"}, "f", "*.DOCX")


def test_list_valued_event_field():
    assert _match_field({"tags": ["x", "y"]}, "tags", "y")


def test_unknown_modifier():
    with pytest.raises(ValueError):
        _match_field({"a": "b"}, "a|bogus", "b")


def test_selection_list_of_maps_is_or_and_keywords():
    sel = [{"a": 1}, {"b": 2}]
    assert _match_selection({"b": 2}, sel)
    assert not _match_selection({"c": 3}, sel)
    assert _match_selection({"msg": "Hello EVIL world"}, ["evil"])
