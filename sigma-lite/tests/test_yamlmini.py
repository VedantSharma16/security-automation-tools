import pytest
from sigmalite import yamlmini as y


def test_nested_map_and_lists():
    doc = y.loads("a: 1\nb:\n  c: 'x # y'  # comment\n  d:\n    - one\n    - 2\ne: [1, 'a,b']\n")
    assert doc == {"a": 1, "b": {"c": "x # y", "d": ["one", 2]}, "e": [1, "a,b"]}


def test_list_of_maps_and_same_indent_list():
    doc = y.loads("sel:\n  - a: 1\n    b: 2\n  - c: 3\nk:\n- x\n- y\n")
    assert doc == {"sel": [{"a": 1, "b": 2}, {"c": 3}], "k": ["x", "y"]}


def test_bools_null_and_keys_with_pipes():
    assert y.loads("Image|endswith: ok\nf: true\nn: null\n") == {"Image|endswith": "ok", "f": True, "n": None}


@pytest.mark.parametrize("bad", ["a: &x 1", "a: 1\na: 2", "\tx: 1", "a: 'open", "a: |\n  text"])
def test_rejects_unsupported(bad):
    with pytest.raises(y.YamlError):
        y.loads(bad)
