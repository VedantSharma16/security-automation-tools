import json
import pytest
from pathlib import Path
from detforge import Rule, RuleError, ConditionError, load_rules
from detforge import condition as cond, report
from detforge.cli import main

ROOT = Path(__file__).resolve().parent.parent


def rule(detection, **kw):
    return Rule.from_dict({"id": "T", "title": "t", "level": "low", "detection": detection, **kw})


def test_bundled_rules_pass_their_embedded_tests():
    rules = load_rules(ROOT / "rules")
    assert len(rules) >= 5
    assert [f for r in rules for f in r.self_test()] == []


@pytest.mark.parametrize("mod,val,actual,exp", [
    ("contains", "ab", "xABy", True), ("startswith", "x", "xab", True), ("endswith", "z", "xab", False),
    ("re", r"^\d+$", "123", True), ("cidr", "10.0.0.0/8", "10.2.3.4", True), ("cidr", "10.0.0.0/8", "11.0.0.1", False),
    ("cidr", "10.0.0.0/8", "garbage", False), ("gt", 5, "6", True), ("lte", 5, "abc", False),
])
def test_modifiers(mod, val, actual, exp):
    assert rule({"s": {f"f|{mod}": val}, "condition": "s"}).matches({"f": actual}) is exp


def test_equals_case_insensitive_and_all_modifier():
    r = rule({"s": {"f|contains|all": ["a", "b"]}, "e": {"g": "HeLLo"}, "condition": "s and e"})
    assert r.matches({"f": "xxAxxB", "g": "hello"})
    assert not r.matches({"f": "xxA", "g": "hello"})


def test_exists_and_nested_fields():
    r = rule({"s": {"a.b|exists": True}, "condition": "s"})
    assert r.matches({"a": {"b": 1}}) and not r.matches({"a": {}})


def test_list_of_maps_is_or():
    r = rule({"s": [{"a": 1}, {"b": 2}], "condition": "s"})
    assert r.matches({"b": 2}) and not r.matches({"a": 2})


def test_condition_precedence_and_quantifiers():
    r = rule({"s1": {"a": 1}, "s2": {"b": 1}, "f": {"c": 1}, "condition": "s1 or s2 and not f"})
    assert r.matches({"a": 1, "c": 1})            # s1 alone satisfies or
    assert not r.matches({"b": 1, "c": 1})
    q = rule({"sel_a": {"a": 1}, "sel_b": {"b": 1}, "condition": "all of sel_*"})
    assert q.matches({"a": 1, "b": 1}) and not q.matches({"a": 1})
    assert rule({"sel_a": {"a": 1}, "x": {"b": 1}, "condition": "1 of them"}).matches({"b": 1})


@pytest.mark.parametrize("bad", ["", "a and", "(a", "a b", "not", "1 of", "a $ b"])
def test_bad_conditions(bad):
    with pytest.raises(ConditionError):
        cond.parse(bad)


@pytest.mark.parametrize("d", [
    {"s": {"a": 1}, "condition": "missing"},
    {"s": {"a|bogus": 1}, "condition": "s"},
    {"s": {"a|re": "("}, "condition": "s"},
    {"s": {"a|cidr": "nope"}, "condition": "s"},
    {"s": {}, "condition": "s"},
    {"condition": "s"},
])
def test_invalid_rules_rejected(d):
    with pytest.raises(RuleError):
        rule(d)


def test_bad_level_tag_and_duplicates(tmp_path):
    with pytest.raises(RuleError):
        Rule.from_dict({"id": "x", "title": "t", "level": "nope", "detection": {"s": {"a": 1}, "condition": "s"}})
    with pytest.raises(RuleError):
        rule({"s": {"a": 1}, "condition": "s"}, tags=["attack.t12"])
    d = {"id": "D", "title": "t", "level": "low", "detection": {"s": {"a": 1}, "condition": "s"}}
    for n in "ab":
        (tmp_path / f"{n}.json").write_text(json.dumps(d))
    with pytest.raises(RuleError, match="duplicate"):
        load_rules(tmp_path)


def test_self_test_detects_regressions():
    r = rule({"s": {"a": 1}, "condition": "s"}, tests={"should_match": [{"a": 2}], "should_not_match": [{"a": 1}]})
    assert len(r.self_test()) == 2


def test_scan_sample_and_reports():
    rules = load_rules(ROOT / "rules")
    events = [json.loads(l) for l in (ROOT / "samples/events.jsonl").read_text().splitlines()]
    hits = report.scan(rules, events)
    assert {h["rule_id"] for h in hits} == {"DF-001", "DF-002", "DF-003", "DF-004", "DF-005"}
    assert report.summarize(hits)["by_level"]["critical"] == 2
    layer = report.navigator_layer(rules)
    assert {t["techniqueID"] for t in layer["techniques"]} >= {"T1059.001", "T1003.001"}


def test_cli(capsys):
    r, s = str(ROOT / "rules"), str(ROOT / "samples/events.jsonl")
    assert main(["validate", r]) == 0
    assert main(["test", r]) == 0
    assert main(["scan", r, s, "--fail-on", "critical"]) == 2
    capsys.readouterr()
    assert main(["scan", r, s, "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["summary"]["total"] >= 5
    assert main(["validate", "/nonexistent"]) == 1
    assert main(["coverage", r, "--navigator"]) == 0
