from sigmalite.matcher import match_field, match_selection


def test_case_insensitive_and_wildcards():
    ev = {"CommandLine": "PowerShell.EXE -Enc abc"}
    assert match_field(ev, "CommandLine", "powershell.exe*")
    assert match_field(ev, "CommandLine|contains", "-enc")
    assert not match_field(ev, "CommandLine", "powershell")
    assert match_field(ev, "CommandLine|endswith", "ABC")


def test_all_modifier_and_list_or():
    ev = {"c": "procdump -ma lsass.exe"}
    assert match_field(ev, "c|contains|all", ["procdump", "lsass"])
    assert not match_field(ev, "c|contains|all", ["procdump", "mimi"])
    assert match_field(ev, "c|contains", ["mimi", "lsass"])


def test_regex_cidr_numeric_exists_base64():
    ev = {"ip": "10.2.3.4", "n": "7", "x": "aGk="}
    assert match_field(ev, "ip|cidr", "10.0.0.0/8")
    assert not match_field(ev, "ip|cidr", "192.168.0.0/16")
    assert match_field(ev, "n|gt", 5) and not match_field(ev, "n|lt", 5)
    assert match_field(ev, "x|re", r"^a\w+=$")
    assert match_field(ev, "x|base64", "hi")
    assert match_field(ev, "ip|exists", True) and match_field(ev, "nope|exists", False)


def test_nested_dotted_and_null():
    ev = {"event": {"outcome": "failure"}, "empty": ""}
    assert match_field(ev, "event.outcome", "failure")
    assert match_field(ev, "missing", None)
    assert match_field(ev, "empty", None)


def test_literal_escaped_wildcard_and_regex_chars():
    assert match_field({"p": "a*b"}, "p", r"a\*b")
    assert not match_field({"p": "axb"}, "p", r"a\*b")
    assert match_field({"p": "a.b"}, "p", "a.b") and not match_field({"p": "axb"}, "p", "a.b")


def test_list_valued_field_and_keywords():
    assert match_field({"tags": ["a", "evil"]}, "tags", "evil")
    assert match_selection({"msg": "found MiMiKatz here"}, ["mimikatz"])
    assert not match_selection({"msg": "clean"}, ["mimikatz"])
