import pytest

from sigmalite.matcher import MatcherError, compile_selection, get_field


def m(selection, event, field_map=None):
    return compile_selection(selection, field_map)(event)


def test_exact_match_is_case_insensitive():
    assert m({"Image": "C:\\Windows\\cmd.exe"}, {"Image": "c:\\windows\\CMD.EXE"})


def test_wildcards_and_escapes():
    assert m({"Image": "*\\cmd.exe"}, {"Image": "C:\\Windows\\cmd.exe"})
    assert m({"Name": "a?c"}, {"Name": "abc"})
    assert not m({"Name": "a\\*c"}, {"Name": "abc"})
    assert m({"Name": "a\\*c"}, {"Name": "a*c"})


def test_regex_special_chars_in_plain_values_are_literal():
    assert not m({"CommandLine": "a.b"}, {"CommandLine": "axb"})


def test_contains_startswith_endswith():
    ev = {"CommandLine": "powershell -enc AAAA"}
    assert m({"CommandLine|contains": "-ENC"}, ev)
    assert m({"CommandLine|startswith": "power"}, ev)
    assert m({"CommandLine|endswith": "aaaa"}, ev)
    assert not m({"CommandLine|startswith": "enc"}, ev)


def test_list_values_are_ored_unless_all():
    ev = {"CommandLine": "vssadmin delete shadows"}
    assert m({"CommandLine|contains": ["nope", "shadows"]}, ev)
    assert m({"CommandLine|contains|all": ["delete", "shadows"]}, ev)
    assert not m({"CommandLine|contains|all": ["delete", "catalog"]}, ev)


def test_mapping_fields_are_anded():
    sel = {"Image|endswith": "\\reg.exe", "CommandLine|contains": "add"}
    assert m(sel, {"Image": "C:\\reg.exe", "CommandLine": "reg add x"})
    assert not m(sel, {"Image": "C:\\reg.exe", "CommandLine": "reg query x"})


def test_list_of_mappings_is_ored():
    sel = [{"Image": "*\\a.exe"}, {"OriginalFileName": "A.EXE"}]
    assert m(sel, {"OriginalFileName": "a.exe"})
    assert not m(sel, {"Image": "b.exe"})


def test_keyword_selection_searches_all_string_values():
    sel = ["mimikatz", "sekurlsa"]
    assert m(sel, {"Process": {"CommandLine": "invoke-Mimikatz -dump"}})
    assert not m(sel, {"CommandLine": "notepad"})


def test_regex_is_case_sensitive_by_default():
    assert m({"CommandLine|re": r"bash\s+-i"}, {"CommandLine": "bash  -i"})
    assert not m({"CommandLine|re": "BASH"}, {"CommandLine": "bash"})
    assert m({"CommandLine|re": "(?i)BASH"}, {"CommandLine": "bash"})


def test_windash_expands_dash_variants():
    sel = {"CommandLine|windash|contains": " -enc "}
    assert m(sel, {"CommandLine": "pwsh /enc AAA"})
    assert m(sel, {"CommandLine": "pwsh \u2013enc AAA"})
    assert not m(sel, {"CommandLine": "pwsh enc AAA"})


def test_cidr():
    sel = {"DestinationIp|cidr": ["10.0.0.0/8", "192.168.0.0/16"]}
    assert m(sel, {"DestinationIp": "10.20.30.40"})
    assert not m(sel, {"DestinationIp": "8.8.8.8"})
    assert not m(sel, {"DestinationIp": "not-an-ip"})


def test_numeric_comparisons():
    assert m({"DestinationPort|gte": 1024}, {"DestinationPort": "4444"})
    assert not m({"DestinationPort|lt": 1024}, {"DestinationPort": 4444})
    assert not m({"DestinationPort|gt": 1}, {"DestinationPort": "abc"})


def test_integer_and_bool_values():
    assert m({"EventID": 1}, {"EventID": 1})
    assert m({"EventID": 1}, {"EventID": "1"})
    assert not m({"EventID": 1}, {"EventID": True})
    assert m({"Initiated": True}, {"Initiated": "true"})


def test_null_and_exists():
    assert m({"ParentImage": None}, {"Image": "x"})
    assert not m({"ParentImage": None}, {"ParentImage": "x"})
    assert m({"ParentImage|exists": True}, {"ParentImage": "x"})
    assert m({"ParentImage|exists": False}, {"Image": "x"})


def test_missing_field_never_matches_wildcard():
    assert not m({"CommandLine": "*"}, {"Image": "x"})


def test_base64_modifier():
    # base64("http://") == "aHR0cDovLw==", but inside a longer payload it encodes as "aHR0cDovL..."
    assert m({"CommandLine|base64|contains": "http://"}, {"CommandLine": "-e aHR0cDovL2V2aWw="})


def test_event_list_value_matches_any_element():
    assert m({"Tags": "evil"}, {"Tags": ["benign", "EVIL"]})


def test_nested_paths_and_field_map():
    ev = {"process": {"executable": "C:\\x\\certutil.exe"}}
    assert get_field(ev, "process.executable") == "C:\\x\\certutil.exe"
    assert m({"Image|endswith": "\\certutil.exe"}, ev, {"Image": "process.executable"})


@pytest.mark.parametrize("bad", [
    {"Image|bogus": "x"},
    {"DestinationIp|cidr": "999.1.1.1/8"},
    {"Port|gt": "abc"},
    {"Image": []},
    {},
    [],
    "just a string",
])
def test_malformed_selections_raise(bad):
    with pytest.raises(MatcherError):
        compile_selection(bad)


def test_base64_exact_keeps_padding():
    assert m({"Payload|base64": "hi"}, {"Payload": "aGk="})
    assert not m({"Payload|base64": "hi"}, {"Payload": "aGk"})
