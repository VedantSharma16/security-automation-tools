from sigma_tuner.yaml_dump import dump


def test_scalars():
    assert dump("hello") == "hello\n"
    assert dump(5) == "5\n"
    assert dump(True) == "true\n"
    assert dump(None) == "null\n"


def test_string_needing_quotes():
    assert dump("selection and not filter") == '"selection and not filter"\n'
    assert dump("10.0.0.5") == '"10.0.0.5"\n'
    assert dump("true") == '"true"\n'  # would otherwise parse back as a bool


def test_flat_dict():
    out = dump({"a": 1, "b": "two"})
    assert out == "a: 1\nb: two\n"


def test_nested_dict_and_list():
    out = dump({"detection": {"selection": {"event_type": "auth_failure"}}, "tags": ["x", "y"]})
    assert "detection:" in out
    assert "  selection:" in out
    assert "    event_type: auth_failure" in out
    assert "tags:" in out
    assert "  - x" in out
    assert "  - y" in out


def test_list_of_quoted_strings():
    out = dump({"src_ip|startswith": ["10.", "192.168."]})
    assert '- "10."' in out
    assert '- "192.168."' in out


def test_empty_containers():
    assert dump({}) == "{}\n"
    assert dump([]) == "[]\n"
    assert dump({"falsepositives": []}) == "falsepositives: []\n"
