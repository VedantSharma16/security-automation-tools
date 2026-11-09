import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sigmalite import Engine, RuleError, load_rules
from sigmalite.cli import main
from sigmalite.condition import ConditionError, evaluate, parse
from sigmalite.matcher import FieldMatcher, MatcherError, Selection
from sigmalite.rule import parse_rule

ROOT = Path(__file__).resolve().parents[1]


def rule(detection, **kw):
    return parse_rule({"title": "t", "id": kw.get("id", "x"), "level": kw.get("level", "low"),
                       "detection": detection, **{k: v for k, v in kw.items() if k not in ("id", "level")}})


# --- matcher ---
def test_equality_case_insensitive_and_wildcard():
    assert FieldMatcher("User", "ROOT").matches({"user": "root"})
    assert FieldMatcher("f", "a*c").matches({"f": "abbbc"})
    assert not FieldMatcher("f", "a*c").matches({"f": "abbbd"})


def test_modifiers():
    assert FieldMatcher("f|contains", "ell").matches({"f": "Hello"})
    assert FieldMatcher("f|startswith", "he").matches({"f": "Hello"})
    assert FieldMatcher("f|endswith", "LO").matches({"f": "Hello"})
    assert FieldMatcher("f|re", r"^h.l+o$").matches({"f": "Hello"})
    assert FieldMatcher("ip|cidr", "10.0.0.0/8").matches({"ip": "10.9.9.9"})
    assert not FieldMatcher("ip|cidr", "10.0.0.0/8").matches({"ip": "not-an-ip"})


def test_all_modifier_requires_every_value():
    m = FieldMatcher("c|contains|all", ["a", "b"])
    assert m.matches({"c": "ab"}) and not m.matches({"c": "a"})


def test_null_matches_missing_and_nested_lookup():
    assert FieldMatcher("x", None).matches({"y": 1})
    assert FieldMatcher("a.b", "1").matches({"A": {"B": 1}})


def test_bad_modifier_and_regex_rejected():
    with pytest.raises(MatcherError):
        FieldMatcher("f|nope", "x")
    with pytest.raises(MatcherError):
        FieldMatcher("f|re", "(")


def test_keyword_selection_searches_all_fields():
    s = Selection(["mimikatz"])
    assert s.matches({"a": {"b": ["xx MimiKatz xx"]}})
    assert not s.matches({"a": "clean"})


def test_list_of_maps_is_or():
    s = Selection([{"a": 1}, {"b": 2}])
    assert s.matches({"b": 2}) and not s.matches({"a": 9})


# --- conditions ---
def ev(text, true=()):
    names = {"a", "b", "c", "sel_1", "sel_2"}
    return evaluate(parse(text, names), lambda n: n in true)


def test_precedence_and_not():
    assert ev("a or b and c", {"a"})
    assert not ev("(a or b) and c", {"a"})
    assert ev("a and not b", {"a"})


def test_quantifiers():
    assert ev("1 of sel_*", {"sel_2"})
    assert not ev("all of sel_*", {"sel_2"})
    assert ev("all of them", {"a", "b", "c", "sel_1", "sel_2"})


@pytest.mark.parametrize("bad", ["", "a and", "a b", "(a", "zzz", "1 of nomatch_*", "a ) "])
def test_bad_conditions(bad):
    with pytest.raises(ConditionError):
        parse(bad, {"a", "b", "c"})


# --- rules ---
def test_rule_validation():
    with pytest.raises(RuleError):
        parse_rule({"title": "t"})
    with pytest.raises(RuleError):
        rule({"s": {"a": 1}, "condition": "missing"})
    with pytest.raises(RuleError):
        parse_rule({"title": "t", "id": "1", "level": "bogus", "detection": {"s": {"a": 1}, "condition": "s"}})


def test_attack_tags_split():
    r = rule({"s": {"a": 1}, "condition": "s"}, tags=["attack.execution", "attack.t1059.001", "attack.t1027"])
    assert r.techniques == ["T1027", "T1059.001"] and r.tactics == ["execution"]


def test_duplicate_ids_rejected(tmp_path):
    body = "title: t\nid: dup\nlevel: low\ndetection: {s: {a: 1}, condition: s}\n"
    (tmp_path / "a.yml").write_text(body)
    (tmp_path / "b.yml").write_text(body)
    with pytest.raises(RuleError, match="duplicate"):
        load_rules(tmp_path)


# --- bundled rules vs sample events ---
@pytest.fixture(scope="module")
def results():
    from sigmalite.engine import read_events
    rules = load_rules(ROOT / "rules")
    out = {}
    for m in Engine(rules).scan(read_events(ROOT / "samples" / "events.jsonl")):
        out.setdefault(m.line, set()).add(m.rule.id)
    return out


def test_bundled_rules_load():
    assert len(load_rules(ROOT / "rules")) >= 6


def test_detections(results):
    assert results[1] == {"sl-0001", "sl-0002"}      # encoded PS spawned by Word
    assert 2 not in results                          # benign
    assert results[3] == {"sl-0003"}                 # comsvcs minidump
    assert results[4] == {"sl-0004"}
    assert results[5] == {"sl-0005"}                 # external IP
    assert 6 not in results                          # private IP
    assert results[7] == {"sl-0006"} and 8 not in results


def test_logsource_category_gates_rules():
    r = rule({"s": {"CommandLine|contains": "x"}, "condition": "s"}, logsource={"category": "process_creation"})
    assert list(Engine([r]).scan([{"CommandLine": "x", "category": "process_creation"}]))
    assert not list(Engine([r]).scan([{"CommandLine": "x", "category": "network_connection"}]))


def test_min_level_filter():
    low = rule({"s": {"a": 1}, "condition": "s"}, id="l", level="low")
    high = rule({"s": {"a": 1}, "condition": "s"}, id="h", level="high")
    assert [m.rule.id for m in Engine([low, high], "high").scan([{"a": 1}])] == ["h"]


# --- CLI ---
def test_cli_scan_json_and_gate(capsys):
    rc = main(["scan", str(ROOT / "rules"), str(ROOT / "samples/events.jsonl"), "--json", "--fail-on-match"])
    assert rc == 1
    data = json.loads(capsys.readouterr().out)
    assert any(d["rule_id"] == "sl-0003" for d in data)


def test_cli_validate_and_coverage(capsys, tmp_path):
    assert main(["validate", str(ROOT / "rules")]) == 0
    assert main(["coverage", str(ROOT / "rules")]) == 0
    assert "T1003.001" in capsys.readouterr().out
    (tmp_path / "bad.yml").write_text("title: x\n")
    assert main(["validate", str(tmp_path)]) == 2


def test_cli_bad_events_file(tmp_path, capsys):
    f = tmp_path / "e.jsonl"
    f.write_text('{"a":1}\nnot json\n')
    assert main(["scan", str(ROOT / "rules"), str(f)]) == 2
    assert ":2:" in capsys.readouterr().err
