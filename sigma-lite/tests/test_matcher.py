import pytest
from sigmalite.matcher import ModifierError, compile_field, compile_selection


def test_exact_case_insensitive():
    assert compile_field("User", "Admin")({"User": "admin"})


def test_wildcards():
    chk = compile_field("Image", "*\\cmd.exe")
    assert chk({"Image": "C:\\Windows\\CMD.EXE"})
    assert not chk({"Image": "C:\\Windows\\cmd.exe.bak"})


def test_contains_any_vs_all():
    ev = {"c": "powershell -w hidden"}
    assert compile_field("c|contains", ["hidden", "nope"])(ev)
    assert not compile_field("c|contains|all", ["hidden", "nope"])(ev)
    assert compile_field("c|contains|all", ["hidden", "-w"])(ev)


def test_startswith_endswith():
    assert compile_field("p|startswith", "C:\\Temp")({"p": "c:\\temp\\x"})
    assert compile_field("p|endswith", ".exe")({"p": "a.EXE"})


def test_regex_and_invalid_regex():
    assert compile_field("c|re", r"\d{3}-\d{4}")({"c": "call 555-1234"})
    with pytest.raises(ModifierError):
        compile_field("c|re", "(unclosed")


def test_cidr():
    chk = compile_field("ip|cidr", "10.0.0.0/8")
    assert chk({"ip": "10.9.9.9"}) and not chk({"ip": "8.8.8.8"}) and not chk({"ip": "garbage"})


def test_numeric_comparison():
    assert compile_field("n|gt", 5)({"n": "10"})
    assert not compile_field("n|gt", 5)({"n": "abc"})


def test_null_and_missing_field():
    assert compile_field("x", None)({})
    assert not compile_field("x", "a")({})


def test_nested_field_and_list_values():
    assert compile_field("a.b", "1")({"a": {"b": 1}})
    assert compile_field("tags|contains", "evil")({"tags": ["ok", "Evil-thing"]})


def test_unknown_modifier_rejected():
    with pytest.raises(ModifierError):
        compile_field("a|bogus", "x")


def test_selection_list_is_or():
    sel = compile_selection([{"a": "1"}, {"b": "2"}])
    assert sel({"b": "2"}) and not sel({"a": "9"})
