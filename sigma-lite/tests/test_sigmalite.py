import json
from pathlib import Path

import pytest

from sigmalite import Engine, Rule, RuleError, load_rules
from sigmalite.cli import main
from sigmalite.condition import ConditionError, parse_condition
from sigmalite.engine import read_jsonl, summarize

ROOT = Path(__file__).resolve().parent.parent


def rule(detection, **kw):
    return Rule.from_dict({"title": "t", "detection": detection, **kw})


def test_exact_match_is_case_insensitive():
    r = rule({"s": {"user": "Root"}, "condition": "s"})
    assert r.matches({"user": "ROOT"})
    assert not r.matches({"user": "bob"})


def test_modifiers():
    assert rule({"s": {"c|contains": "evil"}, "condition": "s"}).matches({"c": "an EVIL thing"})
    assert rule({"s": {"c|startswith": "ab"}, "condition": "s"}).matches({"c": "abc"})
    assert rule({"s": {"c|endswith": ".exe"}, "condition": "s"}).matches({"c": "a.EXE"})
    assert rule({"s": {"c|re": r"^\d{3}$"}, "condition": "s"}).matches({"c": "123"})
    assert not rule({"s": {"c|re": r"^\d{3}$"}, "condition": "s"}).matches({"c": "12a"})


def test_contains_all_requires_every_value():
    r = rule({"s": {"c|contains|all": ["a", "b"]}, "condition": "s"})
    assert r.matches({"c": "ab"})
    assert not r.matches({"c": "a"})


def test_list_values_are_or():
    r = rule({"s": {"c|contains": ["a", "b"]}, "condition": "s"})
    assert r.matches({"c": "xb"}) and not r.matches({"c": "xyz"})


def test_wildcards_and_cidr():
    assert rule({"s": {"f": "foo*bar"}, "condition": "s"}).matches({"f": "fooXXbar"})
    r = rule({"s": {"ip|cidr": "10.0.0.0/8"}, "condition": "s"})
    assert r.matches({"ip": "10.9.9.9"}) and not r.matches({"ip": "8.8.8.8"})
    assert not r.matches({"ip": "not-an-ip"})


def test_null_and_missing_fields():
    r = rule({"s": {"x": None}, "condition": "s"})
    assert r.matches({"y": 1}) and not r.matches({"x": 1})


def test_nested_and_list_fields():
    r = rule({"s": {"a.b": "v"}, "condition": "s"})
    assert r.matches({"a": {"b": "v"}})
    r2 = rule({"s": {"tags": "x"}, "condition": "s"})
    assert r2.matches({"tags": ["w", "x"]})


def test_keyword_selection_and_or_of_maps():
    assert rule({"k": ["mimikatz"], "condition": "k"}).matches({"msg": "ran Mimikatz.exe"})
    r = rule({"s": [{"a": 1}, {"b": 2}], "condition": "s"})
    assert r.matches({"b": 2}) and not r.matches({"a": 9})


def test_condition_precedence_and_not():
    r = rule({"a": {"x": 1}, "b": {"y": 1}, "c": {"z": 1}, "condition": "a or b and not c"})
    assert r.matches({"x": 1, "z": 1})          # a alone suffices
    assert r.matches({"y": 1})                   # b and not c
    assert not r.matches({"y": 1, "z": 1})


def test_quantifiers():
    d = {"sel_a": {"x": 1}, "sel_b": {"y": 1}, "condition": "all of sel_*"}
    assert rule(d).matches({"x": 1, "y": 1}) and not rule(d).matches({"x": 1})
    d["condition"] = "1 of them"
    assert rule(d).matches({"y": 1})


def test_condition_list_is_or():
    r = rule({"a": {"x": 1}, "b": {"y": 1}, "condition": ["a", "b"]})
    assert r.matches({"y": 1})


@pytest.mark.parametrize("bad", ["a and", "(a", "a b", "or a", ")"])
def test_bad_conditions(bad):
    with pytest.raises(ConditionError):
        parse_condition(bad)


@pytest.mark.parametrize("doc", [
    {"detection": {"s": {"a": 1}, "condition": "s"}},                       # no title
    {"title": "t", "detection": {"s": {"a": 1}}},                           # no condition
    {"title": "t", "detection": {"s": {"a": 1}, "condition": "zzz"}},       # undefined selection
    {"title": "t", "level": "apocalyptic", "detection": {"s": {"a": 1}, "condition": "s"}},
    {"title": "t", "detection": {"s": {"a|bogus": 1}, "condition": "s"}},   # unknown modifier
    {"title": "t", "detection": {"s": {"a|re": "("}, "condition": "s"}},    # bad regex
    {"title": "t", "tags": ["attack.t12"], "detection": {"s": {"a": 1}, "condition": "s"}},
])
def test_invalid_rules_rejected(doc):
    with pytest.raises(RuleError):
        Rule.from_dict(doc)


def test_attack_tag_extraction():
    r = rule({"s": {"a": 1}, "condition": "s"}, tags=["attack.execution", "attack.t1059.001"])
    assert r.attack_techniques == ["T1059.001"] and r.attack_tactics == ["execution"]


def test_bundled_rules_all_valid():
    rules, errors = load_rules(ROOT / "rules")
    assert not errors and len(rules) >= 5


def test_sample_scan_end_to_end():
    rules, _ = load_rules(ROOT / "rules")
    events = list(read_jsonl((ROOT / "samples/events.jsonl").read_text().splitlines()))
    assert len(events) == 7  # junk line skipped
    matches = list(Engine(rules).scan(events))
    titles = {m.rule.title for m in matches}
    assert titles == {
        "Suspicious Encoded PowerShell Command", "Office Application Spawning Command Shell",
        "Certutil Used to Download File", "Volume Shadow Copy Deletion",
        "Root SSH Login From External Address",
    }
    ssh = [m for m in matches if "SSH" in m.rule.title]
    assert len(ssh) == 1 and ssh[0].event["src_ip"] == "203.0.113.50"
    assert summarize(matches)["highest_severity"] == "critical"


def test_filter_exclusion():
    r = rule({"p": {"ParentImage|endswith": "winword.exe"}, "f": {"User": "SYSTEM"}, "condition": "p and not f"})
    assert r.matches({"ParentImage": "x\\winword.exe", "User": "bob"})
    assert not r.matches({"ParentImage": "x\\winword.exe", "User": "system"})


def test_cli(capsys):
    assert main(["validate", str(ROOT / "rules")]) == 0
    assert main(["scan", str(ROOT / "rules"), str(ROOT / "samples/events.jsonl"), "--json", "--min-level", "critical"]) == 0
    assert main(["scan", str(ROOT / "rules"), str(ROOT / "samples/events.jsonl"), "--fail-on-match"]) == 1


def test_cli_json_output(capsys):
    main(["scan", str(ROOT / "rules"), str(ROOT / "samples/events.jsonl"), "--json", "--min-level", "critical"])
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["by_level"] == {"critical": 2}
