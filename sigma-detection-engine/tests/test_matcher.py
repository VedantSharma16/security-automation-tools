import base64

import pytest

from sigma_engine.matcher import MatcherError, compile_detection_item, get_field


def m(item, event):
    return compile_detection_item(item)(event)


def test_exact_match_is_case_insensitive():
    assert m({"User": "corp\\admin"}, {"User": "CORP\\Admin"})
    assert not m({"User": "corp\\admin"}, {"User": "CORP\\Admin2"})


def test_wildcards_and_escapes():
    assert m({"Image": "*\\cmd.exe"}, {"Image": "C:\\Windows\\System32\\cmd.exe"})
    assert m({"Name": "a?c"}, {"Name": "abc"})
    assert m({"Name": "lit\\*"}, {"Name": "lit*"})
    assert not m({"Name": "lit\\*"}, {"Name": "literal"})


def test_contains_with_trailing_backslash_regression():
    # Regression: the appended wildcard must not be escaped by a value ending in '\'
    assert m({"CommandLine|contains": "\\AppData\\"}, {"CommandLine": "C:\\Users\\x\\AppData\\Roaming\\a.exe"})


def test_startswith_endswith():
    assert m({"Image|startswith": "C:\\Users\\"}, {"Image": "c:\\users\\bob\\a.exe"})
    assert m({"Image|endswith": "\\a.exe"}, {"Image": "c:\\users\\bob\\a.exe"})
    assert not m({"Image|endswith": "\\a.exe"}, {"Image": "c:\\users\\bob\\a.exe.bak"})


def test_value_list_is_or_and_all_modifier_is_and():
    assert m({"CommandLine|contains": ["foo", "bar"]}, {"CommandLine": "xx bar"})
    assert not m({"CommandLine|contains|all": ["foo", "bar"]}, {"CommandLine": "xx bar"})
    assert m({"CommandLine|contains|all": ["foo", "bar"]}, {"CommandLine": "bar foo"})


def test_map_is_and_list_of_maps_is_or():
    item = [{"A": "1", "B": "2"}, {"C": "3"}]
    assert m(item, {"A": "1", "B": "2"})
    assert not m(item, {"A": "1"})
    assert m(item, {"C": 3})


def test_regex_is_case_sensitive():
    assert m({"CommandLine|re": r"-e\s+/bin/sh"}, {"CommandLine": "nc x 1 -e /bin/sh"})
    assert not m({"CommandLine|re": r"^NC"}, {"CommandLine": "nc"})


def test_cidr():
    item = {"DestinationIp|cidr": ["10.0.0.0/8", "fe80::/10"]}
    assert m(item, {"DestinationIp": "10.1.2.3"})
    assert m(item, {"DestinationIp": "fe80::1"})
    assert not m(item, {"DestinationIp": "8.8.8.8"})
    assert not m(item, {"DestinationIp": "not-an-ip"})


def test_numeric_comparisons():
    assert m({"Port|gte": 1024}, {"Port": "4444"})
    assert not m({"Port|lt": 1024}, {"Port": 4444})
    assert not m({"Port|gt": 1}, {"Port": "abc"})


def test_windash_expands_dash_to_slash_and_unicode_dashes():
    item = {"CommandLine|windash|contains": " -enc "}
    assert m(item, {"CommandLine": "powershell /enc AAA"})
    assert m(item, {"CommandLine": "powershell \u2013enc AAA"})
    assert m(item, {"CommandLine": "powershell -enc AAA"})


def test_base64_modifier():
    encoded = base64.b64encode(b"http://").decode()
    assert m({"CommandLine|base64|contains": "http://"}, {"CommandLine": f"x {encoded} y"})


def test_null_and_exists():
    assert m({"ParentImage": None}, {"Image": "x"})
    assert not m({"ParentImage": None}, {"ParentImage": "x"})
    assert m({"ParentImage|exists": True}, {"ParentImage": "x"})
    assert m({"ParentImage|exists": False}, {})


def test_keywords_search_all_values_including_nested():
    item = ["mimikatz", "sekurlsa"]
    assert m(item, {"a": {"b": ["x", "Invoke-Mimikatz"]}})
    assert not m(item, {"a": "benign"})


def test_numeric_and_boolean_event_values():
    assert m({"EventID": 1}, {"EventID": 1})
    assert m({"Initiated": "true"}, {"Initiated": True})


def test_nested_field_access():
    assert get_field({"process": {"name": "cmd.exe"}}, "process.name") == "cmd.exe"
    assert get_field({"process.name": "flat"}, "process.name") == "flat"
    assert m({"process.parent.name|endswith": "word.exe"}, {"process": {"parent": {"name": "WINWORD.EXE"}}})


def test_list_valued_event_field():
    assert m({"tags": "lateral"}, {"tags": ["recon", "LATERAL"]})


@pytest.mark.parametrize(
    "item",
    [
        {"A|bogus": "x"},
        {"A|contains|startswith": "x"},
        {"A|cidr": "999.1.1.1/8"},
        {"A|re": "("},
        {"A|gt": "abc"},
        {"A|exists": "yes"},
        {"A": []},
        {},
        [],
        [{"A": "1"}, "keyword"],
    ],
)
def test_invalid_items_raise(item):
    with pytest.raises(MatcherError):
        compile_detection_item(item)
