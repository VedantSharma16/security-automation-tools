import json

import pytest

from sigmalite import RuleError, load_rules, scan
from sigmalite import condition as cond
from sigmalite.cli import main
from sigmalite.engine import coverage, read_events
from sigmalite.matchers import FieldMatcher, MatcherError
from sigmalite.rules import parse_rule

from pathlib import Path

ROOT = Path(__file__).parent.parent


def rule(detection, **kw):
    return parse_rule({"id": "T1", "title": "t", "detection": detection, **kw}, "test")


# ---- condition parser ----
@pytest.mark.parametrize("text,res,expected", [
    ("a and b", {"a": True, "b": True}, True),
    ("a and not b", {"a": True, "b": True}, False),
    ("a or b and c", {"a": True, "b": False, "c": False}, True),  # and binds tighter
    ("(a or b) and c", {"a": True, "b": False, "c": False}, False),
    ("1 of sel*", {"sel1": False, "sel2": True, "x": False}, True),
    ("all of sel*", {"sel1": False, "sel2": True, "x": True}, False),
    ("all of them", {"a": True, "b": True}, True),
    ("not (a or b)", {"a": False, "b": False}, True),
])
def test_condition_eval(text, res, expected):
    assert cond.evaluate(cond.parse(text), res) is expected


@pytest.mark.parametrize("bad", ["", "a and", "(a", "a b", "a; import os", "and a", "1 of"])
def test_condition_rejects_bad_syntax(bad):
    with pytest.raises(cond.ConditionError):
        cond.parse(bad)


def test_condition_is_not_eval():
    with pytest.raises(cond.ConditionError):
        cond.parse("__import__('os').system('id')")


# ---- matchers ----
def test_matcher_modifiers():
    ev = {"Cmd": "PowerShell -ENC abc", "Port": 8080, "Ip": "10.2.3.4"}
    assert FieldMatcher("cmd|contains", "-enc").matches(ev)  # case-insensitive field + value
    assert FieldMatcher("Cmd|startswith", "powershell").matches(ev)
    assert FieldMatcher("Cmd|endswith", "ABC").matches(ev)
    assert FieldMatcher("Cmd|re", r"-enc\s+\w+").matches(ev)
    assert FieldMatcher("Port|gt", 1024).matches(ev)
    assert not FieldMatcher("Port|lt", 1024).matches(ev)
    assert FieldMatcher("Ip|cidr", "10.0.0.0/8").matches(ev)
    assert not FieldMatcher("Ip|cidr", "192.168.0.0/16").matches(ev)


def test_matcher_any_vs_all():
    ev = {"c": "alpha beta"}
    assert FieldMatcher("c|contains", ["alpha", "zzz"]).matches(ev)
    assert not FieldMatcher("c|contains|all", ["alpha", "zzz"]).matches(ev)
    assert FieldMatcher("c|contains|all", ["alpha", "beta"]).matches(ev)


def test_matcher_missing_field_and_nested():
    assert not FieldMatcher("nope|contains", "x").matches({"a": 1})
    assert FieldMatcher("proc.name", "cmd.exe").matches({"proc": {"Name": "CMD.EXE"}})
    assert FieldMatcher("tags|contains", "bad").matches({"tags": ["ok", "bad"]})


@pytest.mark.parametrize("key,val", [("f|bogus", "x"), ("f|re", "("), ("f|cidr", "nope"),
                                     ("f|gt", "x"), ("f", []), ("f|contains|re", "x")])
def test_matcher_errors(key, val):
    with pytest.raises(MatcherError):
        FieldMatcher(key, val)


# ---- rules ----
def test_rule_validation_errors():
    with pytest.raises(RuleError, match="condition"):
        rule({"s": {"a": 1}})
    with pytest.raises(RuleError, match="unknown selection"):
        rule({"s": {"a": 1}, "condition": "s and ghost"})
    with pytest.raises(RuleError, match="invalid level"):
        rule({"s": {"a": 1}, "condition": "s"}, level="urgent")
    with pytest.raises(RuleError):
        parse_rule({"title": "x"}, "t")


def test_rule_techniques():
    r = rule({"s": {"a": 1}, "condition": "s"}, tags=["attack.t1059.001", "attack.execution", "attack.T1027"])
    assert r.techniques == ["T1027", "T1059.001"]


def test_duplicate_ids_rejected(tmp_path):
    d = {"id": "X", "title": "t", "detection": {"s": {"a": 1}, "condition": "s"}}
    (tmp_path / "a.json").write_text(json.dumps(d))
    (tmp_path / "b.json").write_text(json.dumps(d))
    with pytest.raises(RuleError, match="duplicate"):
        load_rules(tmp_path)


# ---- bundled rules against sample data ----
@pytest.fixture(scope="module")
def sample_matches():
    rules = load_rules(ROOT / "rules")
    events = read_events((ROOT / "samples" / "events.jsonl").read_text().splitlines())
    return scan(events, rules)


def test_bundled_rules_load():
    assert len(load_rules(ROOT / "rules")) == 5


def test_sample_detections(sample_matches):
    got = sorted((m.line, m.rule.id) for m in sample_matches)
    assert got == [(2, "SL-0001"), (2, "SL-0002"), (3, "SL-0003"), (4, "SL-0004"), (7, "SL-0005")]


def test_internal_rdp_not_flagged(sample_matches):
    assert 5 not in {m.line for m in sample_matches}


def test_min_level_filter():
    rules = load_rules(ROOT / "rules")
    events = read_events((ROOT / "samples" / "events.jsonl").read_text().splitlines())
    assert {m.rule.level for m in scan(events, rules, "critical")} == {"critical"}


def test_coverage():
    cov = coverage(load_rules(ROOT / "rules"))
    assert cov["T1003.001"] == ["SL-0003"]
    assert "T1059.001" in cov


def test_read_events_skips_garbage():
    assert [n for n, _ in read_events(['{"a":1}', "garbage", "", "[1]", '{"b":2}'])] == [1, 5]


# ---- CLI ----
def test_cli_scan_exit_codes(capsys):
    rc = main(["scan", str(ROOT / "rules"), str(ROOT / "samples" / "events.jsonl")])
    assert rc == 1 and "5 match(es)" in capsys.readouterr().out


def test_cli_scan_clean_and_json(tmp_path, capsys):
    f = tmp_path / "e.jsonl"
    f.write_text('{"Image": "calc.exe"}\n')
    assert main(["scan", str(ROOT / "rules"), str(f), "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_cli_validate_and_errors(tmp_path, capsys):
    assert main(["validate", str(ROOT / "rules")]) == 0
    (tmp_path / "bad.json").write_text("{not json")
    assert main(["validate", str(tmp_path)]) == 2
