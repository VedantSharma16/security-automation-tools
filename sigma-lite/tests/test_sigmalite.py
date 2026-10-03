import json
from pathlib import Path

import pytest

from sigmalite import RuleError, scan
from sigmalite.cli import main
from sigmalite.condition import ConditionError, evaluate_condition, parse_condition
from sigmalite.engine import read_events
from sigmalite.matchers import ModifierError, build_field_matcher
from sigmalite.rules import load_rules, rule_from_dict

ROOT = Path(__file__).resolve().parent.parent


def rule(detection, **extra):
    return rule_from_dict({"title": "t", "detection": detection, **extra}, "test")


# ---- matchers
def test_contains_is_case_insensitive():
    m = build_field_matcher("cmd|contains", "WHOAMI")
    assert m({"cmd": "cmd /c whoami /all"})
    assert not m({"cmd": "dir"})


def test_all_modifier_requires_every_value():
    m = build_field_matcher("cmd|contains|all", ["a", "b"])
    assert m({"cmd": "xaxb"}) and not m({"cmd": "xa"})


def test_wildcards_and_escape():
    m = build_field_matcher("f", "a*c?")
    assert m({"f": "abbbcd"}) and not m({"f": "abbbc"})
    assert build_field_matcher("f", r"a\*b")({"f": "a*b"})
    assert not build_field_matcher("f", r"a\*b")({"f": "axb"})


def test_plain_value_is_exact_not_substring():
    assert not build_field_matcher("f", "abc")({"f": "xabcx"})


def test_regex_cidr_numeric():
    assert build_field_matcher("f|re", r"^\d{3}$")({"f": "123"})
    assert build_field_matcher("ip|cidr", "10.0.0.0/8")({"ip": "10.9.9.9"})
    assert not build_field_matcher("ip|cidr", "10.0.0.0/8")({"ip": "11.0.0.1"})
    assert not build_field_matcher("ip|cidr", "10.0.0.0/8")({"ip": "garbage"})
    assert build_field_matcher("p|gt", 10)({"p": "11"})
    assert not build_field_matcher("p|gt", 10)({"p": "abc"})


def test_null_matches_missing_field_and_dotted_paths():
    assert build_field_matcher("x", None)({"y": 1})
    assert build_field_matcher("a.b", 5)({"a": {"b": 5}})
    assert build_field_matcher("a.b", 5)({"a.b": 5})


def test_list_valued_event_field():
    assert build_field_matcher("tags|contains", "evil")({"tags": ["ok", "very evil"]})


def test_bad_modifiers():
    with pytest.raises(ModifierError):
        build_field_matcher("f|bogus", "x")
    with pytest.raises(ModifierError):
        build_field_matcher("f|contains|endswith", "x")


# ---- conditions
def run(cond, **sel):
    return evaluate_condition(parse_condition(cond), {k: (lambda v=v: v) for k, v in sel.items()})


def test_precedence_not_and_or():
    assert run("a or b and c", a=True, b=False, c=False)
    assert not run("(a or b) and c", a=True, b=False, c=False)
    assert run("a and not b", a=True, b=False)


def test_quantifiers():
    sel = dict(sel_a=True, sel_b=False, other=True)
    assert run("1 of sel_*", **sel)
    assert not run("all of sel_*", **sel)
    assert run("all of them", sel_a=True, other=True)
    assert run("1 of them and not all of them", **sel)


def test_lazy_short_circuit():
    def boom():
        raise AssertionError("evaluated")

    assert evaluate_condition(parse_condition("a or b"), {"a": lambda: True, "b": boom})


@pytest.mark.parametrize("bad", ["", "a and", "(a", "a b", "or a", "1 of"])
def test_malformed_conditions(bad):
    with pytest.raises(ConditionError):
        parse_condition(bad)


def test_unmatched_glob_errors():
    with pytest.raises(ConditionError):
        run("1 of zzz*", a=True)


# ---- rules
def test_and_or_selection_semantics():
    r = rule({"s": [{"a": 1, "b": 2}, {"c": 3}], "condition": "s"})
    assert r.matches({"a": 1, "b": 2}) and r.matches({"c": 3})
    assert not r.matches({"a": 1})


def test_keyword_selection():
    r = rule({"kw": ["mimikatz", "sekurlsa"], "condition": "kw"})
    assert r.matches({"x": "ran SEKURLSA::logonpasswords"}) and not r.matches({"x": "calc"})


def test_multiple_conditions_are_ored():
    r = rule({"a": {"x": 1}, "b": {"y": 1}, "condition": ["a", "b"]})
    assert r.matches({"y": 1}) and not r.matches({"z": 1})


def test_attack_techniques_extracted():
    r = rule({"s": {"a": 1}, "condition": "s"}, tags=["attack.execution", "attack.t1059.001", "attack.t1027"])
    assert r.attack_techniques == ["T1059.001", "T1027"]


@pytest.mark.parametrize(
    "data",
    [
        {"detection": {"condition": "s"}},
        {"title": "t"},
        {"title": "t", "detection": {"s": {"a": 1}}},
        {"title": "t", "detection": {"s": {"a": 1}, "condition": "nope"}},
        {"title": "t", "level": "apocalyptic", "detection": {"s": {"a": 1}, "condition": "s"}},
        {"title": "t", "detection": {"s": {}, "condition": "s"}},
        {"title": "t", "detection": {"s": {"a|zzz": 1}, "condition": "s"}},
    ],
)
def test_invalid_rules_rejected(data):
    with pytest.raises(RuleError):
        rule_from_dict(data, "test")


def test_bundled_rules_all_load():
    assert len(load_rules(ROOT / "rules")) >= 6


# ---- engine / CLI
def test_scan_against_sample_events():
    rules = load_rules(ROOT / "rules")
    events = list(read_events((ROOT / "sample_events.jsonl").open()))
    hits = {(m.index, m.rule.title) for m in scan(rules, events)}
    assert (0, "Suspicious Encoded PowerShell Command") in hits
    assert (1, "Office Application Spawns Command Interpreter") in hits
    assert (2, "Credential Dumping via comsvcs or procdump on LSASS") in hits
    assert any(i == 4 for i, _ in hits)  # external root SSH
    assert not any(i == 5 for i, _ in hits)  # internal source filtered
    assert not any(i == 3 for i, _ in hits)  # benign notepad
    assert any(i == 6 for i, _ in hits) and any(i == 7 for i, _ in hits)


def test_min_level_filters():
    rules = load_rules(ROOT / "rules")
    events = list(read_events((ROOT / "sample_events.jsonl").open()))
    assert all(m.rule.level in ("high", "critical") for m in scan(rules, events, "high"))


def test_read_events_array_and_bad_line():
    assert list(read_events(['[{"a":1},{"b":2}]'])) == [{"a": 1}, {"b": 2}]
    with pytest.raises(ValueError, match="line 2"):
        list(read_events(['{"a":1}\n', "nope\n"]))


def test_cli_scan_json_and_exit_codes(capsys):
    args = ["scan", str(ROOT / "rules"), str(ROOT / "sample_events.jsonl"), "--format", "json"]
    assert main(args) == 0
    assert len(json.loads(capsys.readouterr().out)) >= 6
    assert main(args + ["--fail-on-match"]) == 1


def test_cli_validate_and_errors(capsys, tmp_path):
    assert main(["validate", str(ROOT / "rules")]) == 0
    bad = tmp_path / "bad.yml"
    bad.write_text("title: x\n")
    assert main(["validate", str(bad)]) == 2
    assert "error:" in capsys.readouterr().err


def test_contains_value_ending_in_backslash():
    m = build_field_matcher("p|contains", "\\AppData\\")
    assert m({"p": "C:\\Users\\bob\\AppData\\Roaming\\x.exe"})
    assert not m({"p": "C:\\Users\\bob\\AppData*"})
