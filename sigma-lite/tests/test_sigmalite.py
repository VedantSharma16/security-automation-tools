from pathlib import Path

import pytest

from sigmalite import Engine, RuleError, load_rules
from sigmalite.condition import ConditionError, compile_condition
from sigmalite.engine import coverage, read_events
from sigmalite.matchers import build_field_matcher
from sigmalite.rule import parse_rule

ROOT = Path(__file__).parent.parent


def rule(detection, **extra):
    return parse_rule({"title": "t", "id": "x", **extra, "detection": detection})


def test_shipped_rules_self_test_pass():
    engine = Engine(load_rules(ROOT / "rules"))
    assert engine.self_test() == []


def test_modifiers():
    _, p = build_field_matcher("f|contains|all", ["a", "b"])
    assert p({"f": "xxAxxb"}) and not p({"f": "a"})
    _, p = build_field_matcher("f|startswith", "ab")
    assert p({"f": "ABc"})
    _, p = build_field_matcher("ip|cidr", "10.0.0.0/8")
    assert p({"ip": "10.2.3.4"}) and not p({"ip": "11.0.0.1"}) and not p({"ip": "junk"})
    _, p = build_field_matcher("n|gte", 5)
    assert p({"n": "5"}) and not p({"n": "x"})
    _, p = build_field_matcher("f", "a*c")
    assert p({"f": "abbbc"}) and not p({"f": "abd"})


def test_missing_field_and_null():
    _, p = build_field_matcher("f", None)
    assert p({}) and not p({"f": "x"})
    _, p = build_field_matcher("f", "x")
    assert not p({})


def test_list_field_values():
    _, p = build_field_matcher("f|contains", "evil")
    assert p({"f": ["ok", "evil.exe"]})


def test_unsupported_modifier_rejected():
    with pytest.raises(RuleError):
        rule({"s": {"f|base64": "x"}, "condition": "s"})


def test_condition_precedence_and_quantifiers():
    names = ["a", "b", "c1", "c2"]
    f = compile_condition("a or b and not c1", names)
    assert f({"a": False, "b": True, "c1": False, "c2": False})
    assert not f({"a": False, "b": True, "c1": True, "c2": False})
    assert compile_condition("all of c*", names)({"a": 0, "b": 0, "c1": 1, "c2": 1})
    assert not compile_condition("all of c*", names)({"a": 0, "b": 0, "c1": 1, "c2": 0})
    assert compile_condition("1 of them", names)({"a": 0, "b": 0, "c1": 0, "c2": 1})
    assert compile_condition("(a or b) and c1", names)({"a": 1, "b": 0, "c1": 1, "c2": 0})


@pytest.mark.parametrize("bad", ["a and", "zzz", "(a", "1 of nomatch*", "a b"])
def test_bad_conditions(bad):
    with pytest.raises(ConditionError):
        compile_condition(bad, ["a", "b"])


def test_list_of_maps_is_or():
    r = rule({"s": [{"f": "1"}, {"g": "2"}], "condition": "s"})
    assert r.matches({"g": "2"}) and not r.matches({"f": "2"})


def test_duplicate_ids_rejected(tmp_path):
    body = "title: t\nid: dup\ndetection:\n  s: {f: 1}\n  condition: s\n"
    (tmp_path / "a.yml").write_text(body)
    (tmp_path / "b.yml").write_text(body)
    with pytest.raises(RuleError, match="duplicate"):
        load_rules(tmp_path)


def test_self_test_catches_bad_rule():
    r = rule({"s": {"f": "1"}, "condition": "s"}, tests={"match": [{"f": "2"}], "no_match": [{"f": "1"}]})
    assert len(Engine([r]).self_test()) == 2


def test_scan_sample_and_min_level():
    engine = Engine(load_rules(ROOT / "rules"))
    events = list(read_events((ROOT / "samples/events.jsonl").read_text().splitlines()))
    alerts = list(engine.scan(events))
    assert sorted(a.rule_id for a in alerts) == ["sl-0001", "sl-0002", "sl-0003", "sl-0005"]
    assert {a.rule_id for a in engine.scan(events, "critical")} == {"sl-0002"}


def test_read_events_errors():
    with pytest.raises(ValueError, match="line 1"):
        list(read_events(["{bad"]))
    with pytest.raises(ValueError, match="object"):
        list(read_events(["[1]"]))


def test_coverage():
    cov = coverage(load_rules(ROOT / "rules"))
    assert cov["T1003.001"] == ["sl-0004"] and "T1059.001" in cov


def test_cli():
    from sigmalite.cli import main
    assert main(["--rules", str(ROOT / "rules"), "test"]) == 0
    assert main(["--rules", str(ROOT / "rules"), "scan", str(ROOT / "samples/events.jsonl")]) == 1
