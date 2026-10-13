import json

import pytest

from sigmalite.cli import main
from sigmalite.condition import ConditionError, compile_condition
from sigmalite.engine import read_events, scan
from sigmalite.matcher import Selection, get_field
from sigmalite.rules import RuleError, load_rules, parse_rule

from pathlib import Path

ROOT = Path(__file__).parent.parent


def sel(spec, ev):
    return Selection.from_spec(spec).matches(ev)


def test_nested_and_flat_field_lookup():
    assert get_field({"a": {"b": 1}}, "a.b") == 1
    assert get_field({"a.b": 2}, "a.b") == 2
    assert get_field({"a": 1}, "a.b") is None


def test_modifiers_case_insensitive():
    ev = {"cmd": "PowerShell -ENC abc"}
    assert sel({"cmd|contains": "-enc"}, ev)
    assert sel({"cmd|startswith": "powershell"}, ev)
    assert sel({"cmd|endswith": "ABC"}, ev)
    assert not sel({"cmd": "powershell"}, ev)


def test_all_modifier_and_lists():
    ev = {"c": "a b"}
    assert sel({"c|contains|all": ["a", "b"]}, ev)
    assert not sel({"c|contains|all": ["a", "z"]}, ev)
    assert sel({"c|contains": ["z", "b"]}, ev)


def test_regex_cidr_exists_and_list_of_maps():
    assert sel({"c|re": r"^a\d+$"}, {"c": "a12"})
    assert sel({"ip|cidr": "10.0.0.0/8"}, {"ip": "10.9.9.9"})
    assert not sel({"ip|cidr": "10.0.0.0/8"}, {"ip": "nonsense"})
    assert sel({"x|exists": False}, {})
    assert sel([{"a": 1}, {"b": 2}], {"b": 2})


def test_unknown_modifier_and_bad_regex_rejected():
    with pytest.raises(ValueError):
        Selection.from_spec({"a|bogus": 1})
    with pytest.raises(ValueError):
        Selection.from_spec({"a|re": "("})


def test_condition_logic():
    names = ["s1", "s2", "f_a", "f_b"]
    c = compile_condition("s1 and (s2 or not f_a)", names)
    assert c({"s1": True, "s2": False, "f_a": False, "f_b": False})
    assert not c({"s1": True, "s2": False, "f_a": True, "f_b": False})
    assert compile_condition("1 of f_*", names)({"s1": 0, "s2": 0, "f_a": 0, "f_b": 1})
    assert not compile_condition("all of f_*", names)({"s1": 0, "s2": 0, "f_a": 0, "f_b": 1})
    assert compile_condition("all of them", names)({n: True for n in names})


@pytest.mark.parametrize("text", ["s1 and", "unknown", "(s1", "1 of zzz*", "s1 s2"])
def test_condition_errors(text):
    with pytest.raises(ConditionError):
        compile_condition(text, ["s1", "s2"])


def test_rule_validation():
    with pytest.raises(RuleError):
        parse_rule({"title": "x"})
    with pytest.raises(RuleError):
        parse_rule({"title": "x", "level": "nope", "detection": {"a": {"f": 1}, "condition": "a"}})
    r = parse_rule({"title": "x", "tags": ["attack.t1059.001", "attack.execution"],
                    "detection": {"a": {"f": 1}, "condition": "a"}})
    assert r.attack_techniques == ["T1059.001"]


def test_bundled_rules_load():
    assert len(load_rules(ROOT / "rules")) == 5


def test_sample_scan_end_to_end():
    res = scan(load_rules(ROOT / "rules"), read_events(ROOT / "samples/events.jsonl"))
    assert res.events_scanned == 8 and res.skipped_lines == 1
    fired = res.by_rule()
    assert fired == {"SL-001": 1, "SL-002": 1, "SL-003": 1, "SL-004": 1, "SL-005": 1}
    assert res.max_level() == "critical"


def test_cli_scan_and_fail_on(capsys):
    args = ["scan", str(ROOT / "rules"), str(ROOT / "samples/events.jsonl")]
    assert main(args + ["--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["by_technique"]["T1003.001"] == 1
    assert main(args + ["--fail-on", "critical"]) == 2
    assert main(["validate", str(ROOT / "rules")]) == 0
    assert main(["validate", str(ROOT / "nope")]) == 1
