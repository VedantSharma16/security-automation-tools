import json
from pathlib import Path

import pytest

from sigmalite import RuleError, evaluate_events, load_rules
from sigmalite.cli import main
from sigmalite.coverage import coverage
from sigmalite.engine import read_events
from sigmalite.rule import parse_rule

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
SAMPLE = ROOT / "samples" / "events.jsonl"


def doc(**over):
    base = {"title": "t", "detection": {"s": {"a": "b"}, "condition": "s"}}
    base.update(over)
    return base


def test_bundled_rules_load_with_techniques():
    rules = load_rules(RULES)
    assert len(rules) == 5
    assert all(r.techniques for r in rules)


def test_sample_detections_exact():
    rules = load_rules(RULES)
    events = list(read_events(SAMPLE.read_text()))
    hits = {(m.line, m.rule.title) for m in evaluate_events(rules, events)}
    assert hits == {
        (1, "Suspicious Encoded PowerShell Command"),
        (1, "Office Application Spawning Shell"),
        (2, "Office Application Spawning Shell"),
        (3, "LSASS Memory Dump via Common Tools"),
        (5, "Scheduled Task Created via schtasks"),
        (6, "Failed SSH Login From External Range"),
    }


def test_filter_negation_suppresses_alert():
    rules = [r for r in load_rules(RULES) if r.title.startswith("Office")]
    ev = {"ParentImage": r"C:\x\winword.exe", "Image": r"C:\Windows\cmd.exe",
          "CommandLine": r"cmd /c C:\CorpTools\approved.cmd"}
    assert evaluate_events(rules, [ev]) == []


def test_min_level_filters():
    rules = load_rules(RULES)
    events = list(read_events(SAMPLE.read_text()))
    levels = {m.rule.level for m in evaluate_events(rules, events, "high")}
    assert levels <= {"high", "critical"}


def test_list_of_maps_is_or():
    rule = parse_rule(doc(detection={"s": [{"a": "1"}, {"b": "2"}], "condition": "s"}))
    assert rule.matches({"b": "2"}) and not rule.matches({"c": "3"})


def test_condition_list_is_or():
    rule = parse_rule(doc(detection={"x": {"a": 1}, "y": {"b": 2}, "condition": ["x", "y"]}))
    assert rule.matches({"b": 2})


@pytest.mark.parametrize("bad", [
    {"detection": {"s": {"a": 1}, "condition": "s"}},
    doc(level="severe"),
    doc(detection={"s": {"a": 1}}),
    doc(detection={"s": {"a": 1}, "condition": "missing"}),
    doc(detection={"condition": "s"}),
    doc(detection={"s": {}, "condition": "s"}),
    doc(detection={"s": {"a|nope": 1}, "condition": "s"}),
])
def test_invalid_rules_rejected(bad):
    with pytest.raises(RuleError):
        parse_rule(bad)


def test_read_events_formats_and_errors():
    assert len(list(read_events('[{"a":1},{"a":2}]'))) == 2
    with pytest.raises(ValueError):
        list(read_events("{bad"))
    with pytest.raises(ValueError):
        list(read_events("[1]"))


def test_coverage():
    cov = coverage(load_rules(RULES))
    assert "T1003.001" in cov["techniques"] and cov["untagged_rules"] == []
    assert cov["tactics"]["credential_access"] == 2


def test_cli_scan_and_exit_codes(capsys):
    assert main(["scan", str(RULES), str(SAMPLE)]) == 0
    assert main(["scan", str(RULES), str(SAMPLE), "--fail-on-match"]) == 1
    capsys.readouterr()
    assert main(["scan", str(RULES), str(SAMPLE), "--json"]) == 0
    assert len(json.loads(capsys.readouterr().out)) == 6
    assert main(["scan", str(RULES), "/nonexistent"]) == 2


def test_cli_validate_and_coverage(tmp_path, capsys):
    assert main(["validate", str(RULES)]) == 0
    assert main(["coverage", str(RULES)]) == 0
    (tmp_path / "bad.yml").write_text("title: x\n")
    assert main(["validate", str(tmp_path)]) == 2
