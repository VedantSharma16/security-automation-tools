import json
from pathlib import Path

import pytest
import yaml

from sigmalite.cli import main
from sigmalite.condition import ConditionError, compile_condition
from sigmalite.engine import coverage, read_jsonl, scan_events
from sigmalite.matcher import MatcherError, build_field_matcher
from sigmalite.rule import RuleError, load_rules, parse_rule

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
SAMPLE = ROOT / "samples" / "events.jsonl"


def rule(detection, **extra):
    return parse_rule({"title": "t", "id": "x", "detection": detection, **extra})


# --- matcher -------------------------------------------------------------
def test_modifiers():
    ev = {"Cmd": "Foo.EXE --Bar", "Port": "8080", "Ip": "10.2.3.4"}
    assert build_field_matcher("Cmd|contains", "--bar")(ev)
    assert build_field_matcher("Cmd|startswith", "foo")(ev)
    assert build_field_matcher("Cmd|endswith", "bar")(ev)
    assert build_field_matcher("Cmd|re", r"^foo\.exe")(ev)
    assert build_field_matcher("Port|gt", 8000)(ev)
    assert not build_field_matcher("Port|lt", 8000)(ev)
    assert build_field_matcher("Ip|cidr", "10.0.0.0/8")(ev)
    assert build_field_matcher("Cmd", "foo.*")(ev)  # wildcard equality


def test_all_modifier_requires_every_value():
    ev = {"c": "alpha beta"}
    assert build_field_matcher("c|contains|all", ["alpha", "beta"])(ev)
    assert not build_field_matcher("c|contains|all", ["alpha", "gamma"])(ev)
    assert build_field_matcher("c|contains", ["alpha", "gamma"])(ev)


def test_missing_field_and_null():
    assert not build_field_matcher("nope|contains", "x")({})
    assert build_field_matcher("nope", None)({})


def test_nested_field_lookup_case_insensitive():
    assert build_field_matcher("Process.Name", "a.exe")({"process": {"name": "A.EXE"}})


def test_bad_modifier_and_values():
    with pytest.raises(MatcherError):
        build_field_matcher("f|bogus", "x")
    with pytest.raises(MatcherError):
        build_field_matcher("f|re", "(")
    with pytest.raises(MatcherError):
        build_field_matcher("f|cidr", "not-a-net")
    with pytest.raises(MatcherError):
        build_field_matcher("f|gt", "abc")


# --- condition -----------------------------------------------------------
@pytest.mark.parametrize("expr,res,expected", [
    ("a and b", {"a": True, "b": True, "c": False}, True),
    ("a and not b", {"a": True, "b": True, "c": False}, False),
    ("a or b and c", {"a": True, "b": False, "c": False}, True),   # and binds tighter
    ("(a or b) and c", {"a": True, "b": False, "c": False}, False),
    ("1 of them", {"a": False, "b": False, "c": True}, True),
    ("all of them", {"a": True, "b": True, "c": False}, False),
])
def test_condition_eval(expr, res, expected):
    assert compile_condition(expr, ["a", "b", "c"])(res) is expected


def test_condition_glob_quantifier():
    fn = compile_condition("all of sel_*", ["sel_1", "sel_2", "other"])
    assert fn({"sel_1": True, "sel_2": True, "other": False})
    assert not fn({"sel_1": True, "sel_2": False, "other": True})


@pytest.mark.parametrize("expr", ["a and", "a b", "(a", "zzz", "1 of nomatch*", "and a"])
def test_condition_errors(expr):
    with pytest.raises(ConditionError):
        compile_condition(expr, ["a", "b"])


# --- rules ---------------------------------------------------------------
def test_selection_list_of_maps_is_or():
    r = rule({"s": [{"a": 1}, {"b": 2}], "condition": "s"})
    assert r.matches({"b": 2}) and not r.matches({"a": 9, "b": 9})


def test_logsource_filter():
    r = rule({"s": {"a": 1}, "condition": "s"}, logsource={"category": "proc"})
    assert r.matches({"category": "proc", "a": 1})
    assert not r.matches({"category": "net", "a": 1})


def test_techniques_and_tactics():
    r = rule({"s": {"a": 1}, "condition": "s"}, tags=["attack.execution", "attack.t1059.001", "attack.t1027"])
    assert r.techniques == ["T1059.001", "T1027"] and r.tactics == ["execution"]


@pytest.mark.parametrize("bad", [
    {"title": "t", "detection": {"s": {"a": 1}, "condition": "s"}},                 # no id
    {"title": "t", "id": "x", "detection": {"condition": "s"}},                       # no selection
    {"title": "t", "id": "x", "level": "apocalyptic", "detection": {"s": {"a": 1}, "condition": "s"}},
    {"title": "t", "id": "x", "detection": {"s": {"a": 1}, "condition": "s and ghost"}},
    {"title": "t", "id": "x", "detection": {"s": {}, "condition": "s"}},
])
def test_invalid_rules(bad):
    with pytest.raises(RuleError):
        parse_rule(bad)


def test_duplicate_ids_rejected(tmp_path):
    doc = {"title": "t", "id": "dup", "detection": {"s": {"a": 1}, "condition": "s"}}
    for n in "ab":
        (tmp_path / f"{n}.yml").write_text(yaml.safe_dump(doc))
    with pytest.raises(RuleError, match="duplicate"):
        load_rules(tmp_path)


# --- bundled rules + sample data ----------------------------------------
def test_bundled_rules_all_load():
    rules = load_rules(RULES)
    assert len(rules) >= 6 and all(r.techniques for r in rules)


def test_sample_events_fire_expected_rules():
    rules = load_rules(RULES)
    with open(SAMPLE) as fh:
        matches = scan_events(rules, read_jsonl(fh))
    fired = {(m.rule.id, m.line) for m in matches}
    assert fired == {
        ("sl-0001", 2), ("sl-0003", 2),   # encoded PS spawned by Word
        ("sl-0002", 3), ("sl-0004", 4), ("sl-0006", 5),
        ("sl-0005", 6),                   # public RDP only; line 7 is private
    }


def test_min_level_filters():
    rules = load_rules(RULES)
    with open(SAMPLE) as fh:
        matches = scan_events(rules, read_jsonl(fh), "critical")
    assert {m.rule.id for m in matches} == {"sl-0002"}


def test_coverage_maps_techniques():
    cov = coverage(load_rules(RULES))
    assert "T1003.001" in cov and cov["T1003.001"] == ["Credential Dumping via LSASS Access"]


def test_read_jsonl_rejects_bad_json():
    with pytest.raises(ValueError, match="line 2"):
        list(read_jsonl(['{"a":1}', "{oops"]))


# --- CLI -----------------------------------------------------------------
def test_cli_scan_json_and_fail_on_match(capsys):
    code = main(["scan", str(SAMPLE), "--format", "json", "--fail-on-match"])
    out = json.loads(capsys.readouterr().out)
    assert code == 1 and len(out) == 6


def test_cli_validate_and_coverage(capsys):
    assert main(["validate"]) == 0
    assert main(["coverage"]) == 0
    assert "T1059.001" in capsys.readouterr().out


def test_cli_validate_reports_invalid(tmp_path, capsys):
    (tmp_path / "bad.yml").write_text("title: x\n")
    assert main(["validate", "--rules", str(tmp_path)]) == 2
