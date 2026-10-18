import json
import pytest

from sigmalite import RuleError, load_rules, scan_events
from sigmalite.condition import ConditionError, compile_condition
from sigmalite.coverage import coverage
from sigmalite.engine import read_jsonl
from sigmalite.rules import parse_rule
from sigmalite.cli import main

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def rule(detection, **kw):
    return parse_rule({"id": "t", "title": "t", **kw, "detection": detection})


def test_condition_precedence_and_quantifiers():
    names = ["a", "b", "c1", "c2"]
    f, used = compile_condition("a or b and not c1", names)
    assert f({"a": False, "b": True, "c1": False, "c2": False}) is True
    assert f({"a": False, "b": True, "c1": True, "c2": False}) is False
    g, _ = compile_condition("all of c*", names)
    assert g({"a": 0, "b": 0, "c1": True, "c2": True}) and not g({"a": 0, "b": 0, "c1": True, "c2": False})
    h, used = compile_condition("(a or b) and 1 of c*", names)
    assert used == set(names)


@pytest.mark.parametrize("bad", ["", "a and", "a b", "(a", "nope", "1 of zzz*", "and a"])
def test_bad_conditions(bad):
    with pytest.raises(ConditionError):
        compile_condition(bad, ["a", "b"])


def test_modifiers_case_insensitive_and_nested_fields():
    r = rule({"s": {"proc.name|endswith": ".EXE", "cmd|contains|all": ["foo", "bar"]}, "condition": "s"})
    assert r.matches({"Proc": {"Name": "x.exe"}, "CMD": "BAR then FOO"})
    assert not r.matches({"proc": {"name": "x.exe"}, "cmd": "foo only"})


def test_list_values_or_and_selection_list_or():
    r = rule({"s": [{"a": ["1", "2"]}, {"b": "x"}], "condition": "s"})
    assert r.matches({"a": "2"}) and r.matches({"b": "X"}) and not r.matches({"a": "3"})


def test_null_matches_missing_field():
    r = rule({"s": {"user": None}, "condition": "s"})
    assert r.matches({"x": 1}) and not r.matches({"user": "bob"})


def test_regex_modifier():
    r = rule({"s": {"ip|re": r"^10\."}, "condition": "s"})
    assert r.matches({"ip": "10.1.1.1"}) and not r.matches({"ip": "110.1.1.1"})


@pytest.mark.parametrize("doc", [
    {"detection": {"s": {"a": 1}, "condition": "s"}},                # missing keys
    {"id": "x", "title": "x", "level": "urgent", "detection": {"s": {"a": 1}, "condition": "s"}},
    {"id": "x", "title": "x", "detection": {"s": {"a": 1}}},         # no condition
    {"id": "x", "title": "x", "detection": {"s": {"a|bogus": 1}, "condition": "s"}},
    {"id": "x", "title": "x", "detection": {"s": {"a|re": "("}, "condition": "s"}},
    {"id": "x", "title": "x", "detection": {"s": {"a": 1}, "u": {"b": 1}, "condition": "s"}},  # unused
])
def test_invalid_rules(doc):
    with pytest.raises(RuleError):
        parse_rule(doc)


def test_shipped_rules_load_and_tag_techniques():
    rules = load_rules(ROOT / "rules")
    assert len(rules) >= 6
    cov = coverage(rules)
    assert "T1003.001" in cov["techniques"] and not cov["untagged_rules"]


def test_sample_scan_expected_alerts():
    rules = load_rules(ROOT / "rules")
    with open(ROOT / "samples" / "events.jsonl") as fh:
        alerts = scan_events(rules, read_jsonl(fh))
    got = {(a.line, a.rule_id) for a in alerts}
    assert got == {
        (1, "win-ps-encoded"), (1, "win-office-shell"),
        (3, "win-lsass-dump"), (4, "win-schtask-persist"),
        (6, "win-vss-delete"), (7, "lin-ssh-root"),
    }  # benign notepad, SYSTEM schtask and internal ssh must not alert
    assert alerts[0].level == "critical"  # sorted by severity


def test_min_level_filter():
    rules = load_rules(ROOT / "rules")
    with open(ROOT / "samples" / "events.jsonl") as fh:
        alerts = scan_events(rules, read_jsonl(fh), "critical")
    assert {a.rule_id for a in alerts} == {"win-lsass-dump", "win-vss-delete"}


def test_duplicate_ids_rejected(tmp_path):
    for n in "ab":
        (tmp_path / f"{n}.json").write_text(json.dumps(
            {"id": "dup", "title": "t", "detection": {"s": {"a": 1}, "condition": "s"}}))
    with pytest.raises(RuleError, match="duplicate"):
        load_rules(tmp_path)


def test_read_jsonl_errors():
    with pytest.raises(ValueError, match="line 2"):
        list(read_jsonl(['{"a":1}', "{oops"]))
    with pytest.raises(ValueError, match="object"):
        list(read_jsonl(["[1]"]))


def test_cli_exit_codes(capsys):
    assert main(["validate", str(ROOT / "rules")]) == 0
    assert main(["scan", str(ROOT / "rules"), str(ROOT / "samples/events.jsonl")]) == 2
    assert "alert(s)" in capsys.readouterr().out
    assert main(["scan", str(ROOT / "rules"), "/nonexistent"]) == 1
    assert main(["coverage", str(ROOT / "rules"), "--json"]) == 0
