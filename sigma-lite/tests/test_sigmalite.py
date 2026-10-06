import json
from pathlib import Path

import pytest

from sigmalite import cli
from sigmalite.condition import ConditionError, evaluate, parse_condition
from sigmalite.engine import coverage, read_events, run, summarize
from sigmalite.matcher import MatchError, match_field, match_selection
from sigmalite.rules import RuleError, build_rule, lint_rule, load_rules

ROOT = Path(__file__).resolve().parent.parent
RULES, EVENTS = ROOT / "rules", ROOT / "examples" / "events.jsonl"


def ev(cond, **sel):
    return evaluate(parse_condition(cond), sel)


# ---- condition parser ----
def test_precedence_and_over_or():
    assert ev("a or b and c", a=True, b=False, c=False)
    assert not ev("(a or b) and c", a=True, b=False, c=False)


def test_not_and_nested():
    assert ev("not (a and b)", a=True, b=False)


def test_quantifiers():
    r = dict(sel_a=True, sel_b=False, other=True)
    assert ev("1 of sel*", **r)
    assert not ev("all of sel*", **r)
    assert ev("all of them", sel_a=True, sel_b=True)


@pytest.mark.parametrize("bad", ["", "a and", "(a", "a b", "and a", "a or or b"])
def test_malformed_conditions(bad):
    with pytest.raises(ConditionError):
        parse_condition(bad)


def test_unknown_selection():
    with pytest.raises(ConditionError):
        ev("missing", a=True)


# ---- matcher ----
def test_modifiers_case_insensitive():
    e = {"CommandLine": "PowerShell -ENC abc", "n": 5, "ip": "10.2.3.4"}
    assert match_field(e, "CommandLine|contains", "-enc")
    assert match_field(e, "CommandLine|startswith", "powershell")
    assert match_field(e, "CommandLine|endswith", "ABC")
    assert match_field(e, "n|gt", 4) and not match_field(e, "n|lt", 4)
    assert match_field(e, "ip|cidr", "10.0.0.0/8")


def test_all_vs_any():
    e = {"c": "foo bar"}
    assert match_field(e, "c|contains", ["zzz", "foo"])
    assert not match_field(e, "c|contains|all", ["zzz", "foo"])
    assert match_field(e, "c|contains|all", ["bar", "foo"])


def test_wildcards_and_nested_and_null():
    e = {"a": {"b": "hello.exe"}, "z": None}
    assert match_field(e, "a.b", "*.exe")
    assert match_field(e, "z", None)
    assert not match_field(e, "missing", "x")


def test_selection_list_is_or():
    assert match_selection({"a": 1}, [{"a": 2}, {"a": 1}])


def test_bad_modifier():
    with pytest.raises(MatchError):
        match_field({}, "a|bogus", "x")


# ---- rules / lint ----
def good():
    return {"id": "T1", "title": "t", "detection": {"s": {"a": 1}, "condition": "s"}}


def test_lint_clean():
    assert lint_rule(good()) == []


def test_lint_catches_problems():
    r = good()
    r["detection"]["condition"] = "s and ghost"
    r["detection"]["unused"] = {"b": 2}
    r["level"] = "extreme"
    r["tags"] = ["attack.t12"]
    msg = " | ".join(lint_rule(r))
    assert "ghost" in msg and "never used" in msg and "level" in msg and "ATT&CK" in msg
    with pytest.raises(RuleError):
        build_rule(r)


def test_duplicate_ids(tmp_path):
    for n in "ab":
        (tmp_path / f"{n}.json").write_text(json.dumps(good()))
    with pytest.raises(RuleError, match="duplicate"):
        load_rules(tmp_path)


def test_bundled_rules_are_valid():
    rules = load_rules(RULES)
    assert len(rules) >= 6
    assert "T1059.001" in [t for r in rules for t in r.techniques]


# ---- end to end ----
def detections():
    return run(load_rules(RULES), read_events(EVENTS))


def test_sample_attack_chain_detected():
    ids = {d.rule.id for d in detections()}
    assert ids == {"SL-001", "SL-002", "SL-003", "SL-004", "SL-005", "SL-006"}


def test_no_false_positives_on_benign_and_private_rdp():
    lines = {d.line for d in detections()}
    assert 1 not in lines and 6 not in lines  # notepad, internal RDP


def test_lsass_filter_excludes_defender():
    rule = next(r for r in load_rules(RULES) if r.id == "SL-003")
    assert rule.matches({"CommandLine": "x comsvcs.dll", "Image": "C:\\tmp\\x.exe"})
    assert not rule.matches({"CommandLine": "x comsvcs.dll",
                             "Image": "C:\\Program Files\\Windows Defender\\a.exe"})


def test_summary_and_coverage():
    s = summarize(detections())
    assert s["highest_severity"] == "critical" and s["total"] == 6
    assert "T1490" in coverage(load_rules(RULES))


def test_bad_event_line(tmp_path):
    p = tmp_path / "e.jsonl"
    p.write_text('{"a":1}\nnot json\n')
    with pytest.raises(ValueError, match=":2:"):
        list(read_events(p))


# ---- cli ----
def test_cli_run_json_and_gate(capsys):
    assert cli.main(["run", str(RULES), str(EVENTS), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["total"] == 6
    assert cli.main(["run", str(RULES), str(EVENTS), "--fail-on-match"]) == 2


def test_cli_validate_and_coverage(tmp_path, capsys):
    assert cli.main(["validate", str(RULES)]) == 0
    (tmp_path / "bad.json").write_text("{}")
    assert cli.main(["validate", str(tmp_path)]) == 1
    assert cli.main(["coverage", str(RULES)]) == 0
    assert cli.main(["run", "nope", str(EVENTS)]) == 1
