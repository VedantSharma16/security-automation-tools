import json
from pathlib import Path

import pytest
from sigmalite import cli
from sigmalite.coverage import coverage, gaps
from sigmalite.engine import Engine, read_events
from sigmalite.rule import RuleError, from_dict, load_rules

ROOT = Path(__file__).resolve().parent.parent
RULES, EVENTS = ROOT / "rules", ROOT / "samples" / "events.jsonl"


def test_shipped_rules_detect_expected_events():
    matches = list(Engine(load_rules(RULES)).scan(read_events(EVENTS)))
    got = {(m.event_index, m.rule_title) for m in matches}
    assert got == {
        (0, "Encoded PowerShell Command"),
        (2, "Office Application Spawning Shell"),
        (3, "LSASS Credential Dumping Tool"),
        (4, "Failed Login From Public Range"),
    }  # event 1 filtered by allow-list parent, event 5 internal IP, event 6 benign


def test_rule_validation_errors():
    with pytest.raises(RuleError):
        from_dict({"title": "x", "detection": {"a": {"b": 1}}})  # no condition
    with pytest.raises(RuleError):
        from_dict({"title": "x", "level": "nuclear", "detection": {"a": {"b": 1}, "condition": "a"}})
    with pytest.raises(RuleError):
        from_dict({"detection": {}})


def test_list_condition_is_ored():
    r = from_dict({"title": "t", "detection": {"a": {"x": 1}, "b": {"y": 2}, "condition": ["a", "b"]}})
    assert len(list(Engine([r]).scan([{"y": 2}, {"z": 0}]))) == 1


def test_coverage_and_gaps():
    rules = load_rules(RULES)
    rep = coverage(rules)
    assert "T1059.001" in rep["techniques"] and rep["untagged_rules"] == []
    assert gaps(rules, ["t1059", "T1021"]) == ["T1021"]  # sub-technique covers parent


def test_read_events_array_and_bad_json(tmp_path):
    a = tmp_path / "a.json"
    a.write_text('[{"a": 1}]')
    assert list(read_events(a)) == [{"a": 1}]
    b = tmp_path / "b.jsonl"
    b.write_text('{"a": 1}\nnot json\n')
    with pytest.raises(ValueError, match="b.jsonl:2"):
        list(read_events(b))


def test_cli_exit_codes(capsys, tmp_path):
    assert cli.main(["validate", str(RULES)]) == 0
    capsys.readouterr()
    assert cli.main(["scan", str(RULES), str(EVENTS), "--json"]) == 1
    assert len(json.loads(capsys.readouterr().out)) == 4
    clean = tmp_path / "c.jsonl"
    clean.write_text('{"Image": "notepad.exe"}\n')
    assert cli.main(["scan", str(RULES), str(clean)]) == 0
    bad = tmp_path / "bad.yml"
    bad.write_text("title: t\ndetection:\n  a:\n    x: 1\n  condition: ghost\n")
    assert cli.main(["validate", str(bad)]) == 2
    assert cli.main(["validate", str(tmp_path / "missing.yml")]) == 2
    empty = tmp_path / "empty"
    empty.mkdir()
    assert cli.main(["validate", str(empty)]) == 2
