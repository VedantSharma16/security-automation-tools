import json
from pathlib import Path

import pytest

from sigmalite import Engine, RuleError, load_rules
from sigmalite.cli import main
from sigmalite.condition import ConditionError, compile_condition
from sigmalite.coverage import coverage
from sigmalite.engine import read_events
from sigmalite.matchers import match_field
from sigmalite.rule import parse_rule

ROOT = Path(__file__).parent.parent
RULES = ROOT / "rules"
EVENTS = Path(__file__).parent / "fixtures" / "events.ndjson"


# --- matchers ---------------------------------------------------------
def test_modifiers_and_case_insensitivity():
    ev = {"CommandLine": "PowerShell -ENC abc"}
    assert match_field(ev, "CommandLine|contains", "-enc")
    assert match_field(ev, "CommandLine|startswith", "powershell")
    assert not match_field(ev, "CommandLine|cased|contains", "-enc")
    assert match_field(ev, "CommandLine|contains|all", ["-enc", "abc"])
    assert not match_field(ev, "CommandLine|contains|all", ["-enc", "zzz"])


def test_wildcard_regex_numeric_and_nested():
    assert match_field({"a": "foo.exe"}, "a", "*.exe")
    assert match_field({"a": "x123"}, "a|re", r"\d{3}")
    assert match_field({"n": 5}, "n|gt", 3) and not match_field({"n": "x"}, "n|gt", 3)
    assert match_field({"u": {"name": "Bob"}}, "u.name", "bob")
    assert match_field({}, "missing", None)
    assert not match_field({}, "missing", "x")


def test_unknown_modifier_rejected():
    with pytest.raises(ValueError):
        match_field({"a": 1}, "a|bogus", 1)


# --- conditions -------------------------------------------------------
NAMES = ["sel_a", "sel_b", "filter_x"]


@pytest.mark.parametrize("cond,res,expected", [
    ("sel_a and sel_b", dict(sel_a=True, sel_b=False, filter_x=False), False),
    ("sel_a or sel_b", dict(sel_a=False, sel_b=True, filter_x=False), True),
    ("sel_a and not filter_x", dict(sel_a=True, sel_b=False, filter_x=True), False),
    ("1 of sel_*", dict(sel_a=False, sel_b=True, filter_x=False), True),
    ("all of sel_*", dict(sel_a=True, sel_b=False, filter_x=False), False),
    ("1 of them", dict(sel_a=False, sel_b=False, filter_x=True), True),
    ("(sel_a or sel_b) and not filter_x", dict(sel_a=False, sel_b=True, filter_x=False), True),
    ("not sel_a or sel_b", dict(sel_a=True, sel_b=False, filter_x=False), False),
])
def test_conditions(cond, res, expected):
    assert compile_condition(cond, NAMES)(res) is expected


@pytest.mark.parametrize("bad", ["sel_a and", "unknown", "(sel_a", "1 of nothing_*", "sel_a sel_b", ")"])
def test_bad_conditions(bad):
    with pytest.raises(ConditionError):
        compile_condition(bad, NAMES)


# --- rules ------------------------------------------------------------
def test_bundled_rules_load_and_have_attack_tags():
    rules = load_rules(RULES)
    assert len(rules) == 5
    assert all(r.techniques for r in rules)
    assert "T1059.001" in next(r for r in rules if r.id == "sl-0001").techniques


@pytest.mark.parametrize("data", [
    {"detection": {"s": {"a": 1}, "condition": "s"}},
    {"title": "t", "detection": {"condition": "s"}},
    {"title": "t", "level": "nope", "detection": {"s": {"a": 1}, "condition": "s"}},
    {"title": "t", "detection": {"s": {"a": 1}, "condition": "zzz"}},
])
def test_invalid_rules(data):
    with pytest.raises(RuleError):
        parse_rule(data)


def test_duplicate_ids(tmp_path):
    for n in "ab":
        (tmp_path / f"{n}.yml").write_text("title: t\nid: same\ndetection:\n  s: {a: 1}\n  condition: s\n")
    with pytest.raises(RuleError, match="duplicate"):
        load_rules(tmp_path)


# --- engine -----------------------------------------------------------
def test_scan_fixture_expected_alerts():
    matches = list(Engine(load_rules(RULES)).scan(read_events(EVENTS)))
    got = sorted((m.rule.id, m.line) for m in matches)
    # benign powershell (event 2) and svchost->lsass (event 4) must NOT alert
    assert got == [("sl-0001", 1), ("sl-0002", 3), ("sl-0003", 5), ("sl-0004", 6), ("sl-0005", 7)]


def test_min_level_filter():
    ids = {m.rule.id for m in Engine(load_rules(RULES), "critical").scan(read_events(EVENTS))}
    assert ids == {"sl-0002", "sl-0004"}


def test_read_events_json_array_and_bad_line(tmp_path):
    (tmp_path / "a.json").write_text('[{"a": 1}, {"b": 2}]')
    assert len(list(read_events(tmp_path / "a.json"))) == 2
    (tmp_path / "b.ndjson").write_text('{"a": 1}\nnot json\n')
    with pytest.raises(ValueError, match="b.ndjson:2"):
        list(read_events(tmp_path / "b.ndjson"))


# --- coverage & CLI ---------------------------------------------------
def test_coverage():
    cov = coverage(load_rules(RULES))
    assert "credential-access" in cov["tactics"]
    assert "T1003.001" in cov["techniques"]
    assert "exfiltration" in cov["tactic_gaps"]


def test_cli(capsys):
    assert main(["validate", str(RULES)]) == 0
    assert main(["scan", str(RULES), str(EVENTS), "--json"]) == 1  # alerts found
    assert len(json.loads(capsys.readouterr().out.split("OK: 5 rule(s) valid\n")[1])) == 5
    assert main(["coverage", str(RULES)]) == 0
    assert main(["validate", "/nonexistent"]) == 2
