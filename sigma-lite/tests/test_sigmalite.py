from pathlib import Path

import pytest
import yaml

from sigmalite.condition import compile_condition
from sigmalite.coverage import coverage
from sigmalite.engine import read_events, scan
from sigmalite.matcher import RuleError, compile_field_matcher
from sigmalite.rule import load_rules, parse_rule
from sigmalite.cli import main

ROOT = Path(__file__).resolve().parent.parent
RULES, ERRS = load_rules(ROOT / "rules")


def rule(yaml_text):
    return parse_rule(yaml.safe_load(yaml_text))


# ---- matcher ----
def test_contains_case_insensitive():
    assert compile_field_matcher("A|contains", "bar")({"a": "FooBARbaz"})

def test_endswith_list_is_or():
    m = compile_field_matcher("Image|endswith", ["\\a.exe", "\\b.exe"])
    assert m({"Image": "C:\\x\\b.exe"}) and not m({"Image": "C:\\x\\c.exe"})

def test_all_modifier():
    m = compile_field_matcher("C|contains|all", ["x", "y"])
    assert m({"C": "xy"}) and not m({"C": "x"})

def test_wildcard_and_exact():
    m = compile_field_matcher("F", "ab*d")
    assert m({"F": "abcd"}) and not m({"F": "abcde"})

def test_regex_cidr_numeric():
    assert compile_field_matcher("C|re", r"net1?\s+user")({"C": "net1 user"})
    assert compile_field_matcher("IP|cidr", "10.0.0.0/8")({"IP": "10.2.3.4"})
    assert not compile_field_matcher("IP|cidr", "10.0.0.0/8")({"IP": "junk"})
    assert compile_field_matcher("P|gte", 10)({"P": "10"})
    assert not compile_field_matcher("P|lt", 10)({"P": "abc"})

def test_missing_field_and_null():
    assert not compile_field_matcher("A", "x")({})
    assert compile_field_matcher("A", None)({})
    assert compile_field_matcher("A|exists", True)({"a": 1})

def test_nested_field():
    assert compile_field_matcher("process.name", "x.exe")({"process": {"Name": "x.exe"}})

@pytest.mark.parametrize("key,val", [("A|bogus", "x"), ("A|contains|re", "x"),
                                     ("A|re", "("), ("A|cidr", "nope"), ("A|gt", "zz"), ("A", [])])
def test_bad_matchers(key, val):
    with pytest.raises(RuleError):
        compile_field_matcher(key, val)


# ---- condition ----
NAMES = ["sel_a", "sel_b", "filter"]
def ev(cond, **r):
    return compile_condition(cond, NAMES).evaluate({"sel_a": False, "sel_b": False, "filter": False, **r})

def test_precedence_and_over_or():
    assert ev("sel_a or sel_b and filter", sel_a=True)
    assert not ev("sel_a or sel_b and filter", sel_b=True)

def test_not_and_parens():
    assert ev("(sel_a or sel_b) and not filter", sel_b=True)
    assert not ev("(sel_a or sel_b) and not filter", sel_b=True, filter=True)

def test_of_patterns():
    assert ev("1 of sel_*", sel_b=True)
    assert not ev("all of sel_*", sel_b=True)
    assert ev("all of them", sel_a=True, sel_b=True, filter=True)

@pytest.mark.parametrize("bad", ["", "sel_a and", "(sel_a", "sel_a)", "nope", "1 of zzz*", "sel_a sel_b"])
def test_bad_conditions(bad):
    with pytest.raises(RuleError):
        compile_condition(bad, NAMES)


# ---- rules ----
def test_shipped_rules_all_valid():
    assert ERRS == [] and len(RULES) == 7
    assert all(r.techniques for r in RULES)

def test_unused_selection_rejected():
    with pytest.raises(RuleError, match="unused"):
        rule("title: t\nid: x\ndetection:\n  a: {F: 1}\n  b: {F: 2}\n  condition: a\n")

def test_missing_fields_and_level():
    with pytest.raises(RuleError):
        parse_rule({"title": "t"})
    with pytest.raises(RuleError, match="level"):
        rule("title: t\nid: x\nlevel: spicy\ndetection:\n  a: {F: 1}\n  condition: a\n")

def test_duplicate_ids(tmp_path):
    body = "title: t\nid: dup\ndetection:\n  a: {F: 1}\n  condition: a\n"
    (tmp_path / "a.yml").write_text(body); (tmp_path / "b.yml").write_text(body)
    rules, errs = load_rules(tmp_path)
    assert len(rules) == 1 and "duplicate" in errs[0][1]

def test_tags_parsed():
    r = rule("title: t\nid: x\ntags: [attack.execution, attack.t1059.001]\n"
             "detection:\n  a: {F: 1}\n  condition: a\n")
    assert r.techniques == ["T1059.001"] and r.tactics == ["execution"]

def test_condition_list_is_or():
    r = rule("title: t\nid: x\ndetection:\n  a: {F: 1}\n  b: {F: 2}\n  condition: [a, b]\n")
    assert r.matches({"F": 2})


# ---- engine / coverage / cli ----
def alerts():
    return scan(RULES, read_events(ROOT / "samples" / "events.jsonl"))

def titles():
    return [a.title for a in alerts()]

def test_expected_detections():
    t = titles()
    assert "Encoded PowerShell Command" in t
    assert "Office Application Spawns Shell" in t
    assert "LSASS Memory Dump Tooling" in t
    assert "Shadow Copy Deletion" in t
    assert "Account Discovery Commands" in t

def test_filter_and_cidr_suppress_false_positives():
    t = titles()
    assert t.count("Scheduled Task Created From User-Writable Path") == 1  # MS path filtered
    assert t.count("Outbound Connection To Non-Standard C2 Port") == 1     # internal IP excluded

def test_benign_event_silent():
    assert all(a.line != 9 for a in alerts())

def test_min_level_filter():
    assert {a.level for a in scan(RULES, read_events(ROOT / "samples/events.jsonl"), "critical")} == {"critical"}

def test_malformed_jsonl_skipped():
    assert len(list(read_events(ROOT / "samples/events.jsonl"))) == 9

def test_coverage():
    c = coverage(RULES)
    assert "T1003.001" in c["techniques"] and "credential_access" in c["tactics"]
    assert "exfiltration" in c["tactic_gaps"]

def test_cli(capsys):
    assert main(["validate", str(ROOT / "rules")]) == 0
    assert main(["scan", str(ROOT / "rules"), str(ROOT / "samples/events.jsonl"), "--fail-on-alert"]) == 1
    assert "alert(s)" in capsys.readouterr().out
    assert main(["coverage", str(ROOT / "rules")]) == 0
