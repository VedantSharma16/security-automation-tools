from pathlib import Path

import pytest

from sigmalite.cli import main
from sigmalite.condition import ConditionError, parse_condition
from sigmalite.engine import Engine, read_jsonl
from sigmalite.matcher import FieldMatcher, MatcherError
from sigmalite.rules import RuleError, load_rules, parse_rule

ROOT = Path(__file__).parent.parent
RULES = ROOT / "rules"
SAMPLE = ROOT / "samples" / "events.jsonl"


def rule(detection, **extra):
    return parse_rule({"title": "t", "detection": detection, **extra})


def test_modifiers_and_case_insensitivity():
    assert FieldMatcher("a|contains", "BAD").matches({"a": "xxbadxx"})
    assert FieldMatcher("a|startswith", "C:\\").matches({"a": "c:\\x"})
    assert FieldMatcher("a|endswith", ".EXE").matches({"a": "p.exe"})
    assert FieldMatcher("a|re", r"^\d+$").matches({"a": "123"})
    assert not FieldMatcher("a", "x").matches({})


def test_contains_all_vs_any():
    ev = {"a": "one two"}
    assert FieldMatcher("a|contains|all", ["one", "two"]).matches(ev)
    assert not FieldMatcher("a|contains|all", ["one", "three"]).matches(ev)
    assert FieldMatcher("a|contains", ["one", "three"]).matches(ev)


def test_wildcard_cidr_and_nested_fields():
    assert FieldMatcher("a", "foo*bar").matches({"a": "fooXXbar"})
    assert FieldMatcher("src.ip|cidr", "10.0.0.0/8").matches({"src": {"ip": "10.2.3.4"}})
    assert not FieldMatcher("ip|cidr", "10.0.0.0/8").matches({"ip": "not-an-ip"})
    assert FieldMatcher("src.ip", "1.1.1.1").matches({"src.ip": "1.1.1.1"})


def test_bad_modifier_regex_and_cidr_rejected():
    for key, val in [("a|bogus", "x"), ("a|re", "("), ("a|cidr", "nope")]:
        with pytest.raises(MatcherError):
            FieldMatcher(key, val)


def test_condition_precedence_and_quantifiers():
    r = rule({"s1": {"a": "1"}, "s2": {"b": "2"}, "f": {"c": "3"},
              "condition": "s1 or s2 and not f"})
    assert r.matches({"a": "1", "c": "3"})  # and binds tighter than or
    assert not r.matches({"b": "2", "c": "3"})
    r2 = rule({"x_a": {"a": "1"}, "x_b": {"b": "2"}, "condition": "all of x_*"})
    assert r2.matches({"a": "1", "b": "2"}) and not r2.matches({"a": "1"})
    r3 = rule({"x_a": {"a": "1"}, "x_b": {"b": "2"}, "condition": "1 of them"})
    assert r3.matches({"b": "2"})


def test_list_of_maps_is_or():
    r = rule({"s": [{"a": "1"}, {"b": "2"}], "condition": "s"})
    assert r.matches({"b": "2"}) and not r.matches({"a": "2"})


@pytest.mark.parametrize("cond", ["nope", "s and", "(s", "1 of zzz*", "s s"])
def test_condition_errors(cond):
    with pytest.raises(ConditionError):
        parse_condition(cond, ["s"])


def test_rule_validation_errors():
    with pytest.raises(RuleError):
        parse_rule({"title": "x"})
    with pytest.raises(RuleError):
        parse_rule({"title": "x", "level": "urgent", "detection": {"s": {"a": 1}, "condition": "s"}})
    with pytest.raises(RuleError):
        rule({"s": {"a": 1}, "condition": "s"}, tags=["attack.t12"])


def test_attack_mapping():
    r = rule({"s": {"a": 1}, "condition": "s"}, tags=["attack.execution", "attack.t1059.001"])
    assert r.techniques == ["T1059.001"] and r.tactics == ["execution"]


def test_bundled_rules_load_and_detect_sample():
    engine = Engine(load_rules(RULES))
    with SAMPLE.open() as fh:
        alerts = engine.scan(read_jsonl(fh))
    fired = {a.rule_id for a in alerts}
    assert fired == {f"sl-000{i}" for i in range(1, 8)}
    # benign events (updater task, internal login, notepad) must not alert
    assert {6, 8, 10}.isdisjoint({a.line for a in alerts})


def test_min_level_filter():
    engine = Engine(load_rules(RULES), min_level="critical")
    with SAMPLE.open() as fh:
        alerts = engine.scan(read_jsonl(fh))
    assert {a.level for a in alerts} == {"critical"}


def test_duplicate_ids_rejected(tmp_path):
    f = tmp_path / "r.yml"
    doc = "title: a\nid: dup\ndetection:\n  s: {a: 1}\n  condition: s\n"
    f.write_text(doc + "---\n" + doc)
    with pytest.raises(RuleError, match="duplicate"):
        load_rules(f)


def test_malformed_jsonl_reports_line():
    with pytest.raises(ValueError, match="line 2"):
        list(read_jsonl(['{"a":1}', "{oops"]))


def test_cli_scan_and_fail_on(capsys):
    assert main(["scan", str(SAMPLE), "-r", str(RULES)]) == 0
    assert "T1059.001" in capsys.readouterr().out
    assert main(["scan", str(SAMPLE), "-r", str(RULES), "--fail-on", "critical"]) == 1
    assert main(["scan", str(SAMPLE), "-r", str(RULES), "--format", "json"]) == 0
    assert '"total"' in capsys.readouterr().out


def test_cli_errors(capsys):
    assert main(["scan", "missing.jsonl", "-r", str(RULES)]) == 2
    assert main(["validate", str(RULES)]) == 0
