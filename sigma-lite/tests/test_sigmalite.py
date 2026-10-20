import json
from pathlib import Path

import pytest

from sigmalite import yamlsubset
from sigmalite.cli import main
from sigmalite.condition import ConditionError, parse_condition
from sigmalite.engine import evaluate, load_events, summarize
from sigmalite.rules import RuleError, load_rules, rule_from_dict

ROOT = Path(__file__).resolve().parent.parent
RULES, SAMPLES = ROOT / "rules", ROOT / "samples" / "events.json"


def make(detection, **kw):
    return rule_from_dict({"title": "t", "detection": detection, **kw})


def test_yaml_subset_structures():
    doc = yamlsubset.loads(
        "title: 'It''s'\nn: 3\nflag: true\nempty:\nlist: [a, \"b,c\"]\n"
        "tags:\n  - x  # comment\n  - y\nmap:\n  k: v\n  items:\n    - a: 1\n      b: 2\n    - a: 3\n"
    )
    assert doc["title"] == "It's" and doc["n"] == 3 and doc["flag"] is True
    assert doc["empty"] is None and doc["list"] == ["a", "b,c"] and doc["tags"] == ["x", "y"]
    assert doc["map"]["items"] == [{"a": 1, "b": 2}, {"a": 3}]


def test_yaml_rejects_tabs():
    with pytest.raises(yamlsubset.YamlError):
        yamlsubset.loads("a:\n\tb: 1\n")


def test_modifiers_and_case_insensitivity():
    r = make({"s": {"CommandLine|contains": "MiniDump"}, "condition": "s"})
    assert r.matches({"commandline": "rundll32 minidump 1"})
    assert not r.matches({"CommandLine": "other"})


def test_contains_all_requires_every_value():
    r = make({"s": {"c|contains|all": ["a", "b"]}, "condition": "s"})
    assert r.matches({"c": "xaxb"}) and not r.matches({"c": "xa"})


def test_wildcard_equality_and_null():
    r = make({"s": {"u": "adm*"}, "n": {"x": None}, "condition": "s and n"})
    assert r.matches({"u": "Administrator"}) and not r.matches({"u": "guest"})
    assert not r.matches({"u": "admin", "x": "set"})


def test_nested_field_lookup():
    r = make({"s": {"process.name": "cmd.exe"}, "condition": "s"})
    assert r.matches({"process": {"name": "cmd.exe"}})


def test_list_of_maps_is_or_and_keywords():
    r = make({"s": [{"a": 1}, {"b": 2}], "k": ["evil"], "condition": "s or k"})
    assert r.matches({"b": 2}) and r.matches({"msg": "very EVIL"}) and not r.matches({"a": 9})


def test_condition_precedence_and_quantifiers():
    sels = {"sel_a": {"a": 1}, "sel_b": {"b": 1}, "f": {"c": 1}}
    r = make({**sels, "condition": "1 of sel_* and not f"})
    assert r.matches({"a": 1}) and not r.matches({"a": 1, "c": 1})
    r = make({**sels, "condition": "all of sel_*"})
    assert r.matches({"a": 1, "b": 1}) and not r.matches({"a": 1})
    r = make({**sels, "condition": "sel_a or sel_b and f"})
    assert r.matches({"a": 1}) and not r.matches({"b": 1})  # 'and' binds tighter


@pytest.mark.parametrize("bad", ["", "a and", "(a", "a b", "and a", "1 of"])
def test_bad_conditions(bad):
    with pytest.raises(ConditionError):
        parse_condition(bad)


def test_rule_validation_errors():
    with pytest.raises(RuleError, match="undefined"):
        make({"s": {"a": 1}, "condition": "s and ghost"})
    with pytest.raises(RuleError, match="modifier"):
        make({"s": {"a|bogus": 1}, "condition": "s"})
    with pytest.raises(RuleError, match="level"):
        make({"s": {"a": 1}, "condition": "s"}, level="severe")
    with pytest.raises(RuleError, match="regex"):
        make({"s": {"a|re": "("}, "condition": "s"})


def test_attack_tag_extraction():
    r = make({"s": {"a": 1}, "condition": "s"}, tags=["attack.execution", "attack.t1059.001"])
    assert r.attack_techniques == ["T1059.001"] and r.attack_tactics == ["execution"]


def test_bundled_rules_against_samples():
    rules = load_rules(RULES)
    assert len(rules) == 4
    summary = summarize(evaluate(rules, load_events(SAMPLES)))
    got = {h["id"]: h["event_indexes"] for h in summary["hits"]}
    assert got == {"encoded-powershell": [1], "office-spawns-shell": [2],
                   "lsass-minidump": [4], "admin-group-add": [5]}
    assert summary["hits"][0]["level"] == "critical"  # severity-sorted
    assert "T1003.001" in summary["techniques"]


def test_min_level_filters():
    m = evaluate(load_rules(RULES), load_events(SAMPLES), min_level="critical")
    assert {x.rule.id for x in m} == {"office-spawns-shell", "lsass-minidump"}


def test_ndjson_loading(tmp_path):
    f = tmp_path / "e.ndjson"
    f.write_text('{"a":1}\n\n{"a":2}\n')
    assert load_events(f) == [{"a": 1}, {"a": 2}]
    f.write_text('{"a":1}\nnot json\n')
    with pytest.raises(ValueError, match="line 2"):
        load_events(f)


def test_cli_exit_codes_and_json(capsys):
    assert main(["validate", "--rules", str(RULES)]) == 0
    assert main(["scan", "--rules", str(RULES), "--events", str(SAMPLES), "--format", "json"]) == 1
    assert json.loads(capsys.readouterr().out.split("\n", 1)[1])["rules_triggered"] == 4
    assert main(["scan", "--rules", str(RULES), "--events", "/nonexistent"]) == 2
