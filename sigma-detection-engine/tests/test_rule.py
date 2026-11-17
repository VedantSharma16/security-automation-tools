from pathlib import Path

import pytest

from sigmalite.rule import RuleError, load_rule, load_rules, rule_from_dict

BASE = {
    "title": "Test Rule",
    "id": "r1",
    "level": "high",
    "tags": ["attack.execution", "attack.t1059.001", "attack.T1027", "cve.2021-44228"],
    "logsource": {"product": "windows", "category": "process_creation"},
    "detection": {"sel": {"Image|endswith": "\\powershell.exe"}, "condition": "sel"},
}


def make(**overrides):
    data = {**BASE, **overrides}
    return rule_from_dict(data).compile()


def test_compile_and_match():
    rule = make()
    assert rule.matches({"Image": "C:\\x\\powershell.exe"})
    assert not rule.matches({"Image": "C:\\x\\cmd.exe"})


def test_attack_tags_are_parsed():
    rule = make()
    assert rule.techniques == ["T1059.001", "T1027"]
    assert rule.tactics == ["execution"]


def test_applies_to_logsource():
    rule = make()
    assert rule.applies_to(None)
    assert rule.applies_to({"product": "Windows"})
    assert not rule.applies_to({"product": "linux", "category": "process_creation"})
    assert not rule.applies_to({"category": "network_connection"})


@pytest.mark.parametrize("overrides, msg", [
    ({"level": "urgent"}, "invalid level"),
    ({"detection": {"sel": {"Image": "x"}}}, "no 'condition'"),
    ({"detection": {"condition": "sel"}}, "no selections"),
    ({"detection": {"sel": {"Image": "x"}, "condition": "other"}}, "unknown selection"),
    ({"detection": {"sel": {"Image|nope": "x"}, "condition": "sel"}}, "unsupported modifier"),
    ({"tests": {"maybe": []}}, "'tests' may only"),
    ({"detection": "sel"}, "must be a mapping"),
])
def test_invalid_rules(overrides, msg):
    with pytest.raises(RuleError, match=msg):
        make(**overrides)


def test_missing_required_fields():
    with pytest.raises(RuleError, match="missing required"):
        rule_from_dict({"detection": {}})


def test_load_rule_reports_bad_yaml(tmp_path: Path):
    p = tmp_path / "bad.yml"
    p.write_text("title: [unclosed\n")
    with pytest.raises(RuleError, match="invalid YAML"):
        load_rule(p)


def test_load_rules_rejects_duplicate_ids(tmp_path: Path):
    body = "title: T\nid: same\ndetection:\n  sel: {Image: x}\n  condition: sel\n"
    (tmp_path / "a.yml").write_text(body)
    (tmp_path / "b.yaml").write_text(body)
    with pytest.raises(RuleError, match="duplicate rule id"):
        load_rules(tmp_path)


def test_load_rules_recurses_directories(tmp_path: Path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "a.yml").write_text("title: A\ndetection:\n  s: {X: 1}\n  condition: s\n")
    (tmp_path / "notes.txt").write_text("ignored")
    rules = load_rules(tmp_path)
    assert [r.title for r in rules] == ["A"]
    assert rules[0].level == "medium"  # default


def test_load_rules_errors_on_missing_or_empty_source(tmp_path: Path):
    with pytest.raises(RuleError, match="no such file"):
        load_rules(tmp_path / "nope")
    with pytest.raises(RuleError, match="no .yml"):
        load_rules(tmp_path)
