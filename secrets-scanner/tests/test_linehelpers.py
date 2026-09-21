from secretscan.linehelpers import extract_context_key, looks_binary


def test_extract_context_key_python_assignment():
    assert extract_context_key("API_KEY = 'value'") == "API_KEY"


def test_extract_context_key_yaml_style():
    assert extract_context_key("  api_key: value") == "api_key"


def test_extract_context_key_quoted_json_style():
    assert extract_context_key('  "apiKey": "value"') == "apiKey"


def test_extract_context_key_returns_none_when_no_assignment():
    assert extract_context_key("just some text with no assignment") is None


def test_looks_binary_detects_null_byte():
    assert looks_binary(b"hello\x00world")


def test_looks_binary_false_for_text():
    assert not looks_binary(b"hello world\n")
