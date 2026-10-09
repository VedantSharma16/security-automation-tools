import json
from pathlib import Path

import pytest

from sigmalite import cli, engine, report
from sigmalite.rules import RuleError, build_rule, load_rules, parse_timespan

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
EVENTS = ROOT / "samples" / "events.jsonl"


def rule(detection, **kw):
    return build_rule({"title": "t", "detection": detection, **kw}, "test")


def test_parse_timespan():
    assert parse_timespan("2m") == 120
    with pytest.raises(RuleError):
        parse_timespan("2weeks")


def test_missing_selection_reference():
    with pytest.raises(RuleError, match="undefined selection"):
        rule({"a": {"x": 1}, "condition": "a and b"})


def test_bad_level_and_missing_keys():
    with pytest.raises(RuleError):
        rule({"a": {"x": 1}, "condition": "a"}, level="severe")
    with pytest.raises(RuleError):
        build_rule({"title": "x"}, "t")


def test_aggregation_requires_timeframe():
    with pytest.raises(RuleError, match="timeframe"):
        rule({"a": {"x": 1}, "condition": "a | count() > 3"})


def test_keyword_selection():
    r = rule({"kw": ["mimikatz"], "condition": "kw"})
    assert r.matches({"msg": "ran MimiKatz.exe"})
    assert not r.matches({"msg": "calc"})


def test_list_of_maps_is_or():
    r = rule({"s": [{"a": 1}, {"b": 2}], "condition": "s"})
    assert r.matches({"b": 2}) and not r.matches({"a": 9})


def test_attack_tags():
    r = rule({"a": {"x": 1}, "condition": "a"},
             tags=["attack.execution", "attack.t1059.001"])
    assert r.techniques == ["T1059.001"] and r.tactics == ["execution"]


def test_load_shipped_rules_and_duplicates(tmp_path):
    assert len(load_rules(RULES)) == 5
    (tmp_path / "a.yml").write_text("title: x\nid: dup\ndetection: {s: {a: 1}, condition: s}\n")
    (tmp_path / "b.yml").write_text("title: y\nid: dup\ndetection: {s: {a: 1}, condition: s}\n")
    with pytest.raises(RuleError, match="duplicate"):
        load_rules(tmp_path)


def test_end_to_end_sample():
    alerts = engine.run(load_rules(RULES), engine.read_events(EVENTS))
    ids = sorted(a.rule_id for a in alerts)
    # Service account (filter) and internal RDP source are suppressed.
    assert ids == ["sl-0001", "sl-0002", "sl-0003", "sl-0004", "sl-0005"]
    ssh = next(a for a in alerts if a.rule_id == "sl-0004")
    assert ssh.group == "198.51.100.7" and ssh.event_count == 5


def test_threshold_alerts_once_and_rearms():
    r = rule({"f": {"a": 1}, "timeframe": "10s", "condition": "f | count() >= 2"})
    mk = lambda t: {"a": 1, "time": t}
    # burst of 3 -> one alert; gap drains the window; new burst -> second alert
    events = [mk(0), mk(1), mk(2), mk(100), mk(101)]
    assert len(engine.run([r], events)) == 2


def test_threshold_window_expiry():
    r = rule({"f": {"a": 1}, "timeframe": "10s", "condition": "f | count() >= 3"})
    events = [{"a": 1, "time": t} for t in (0, 6, 12, 18)]
    assert engine.run([r], events) == []


def test_coverage_and_summary():
    rules = load_rules(RULES)
    cov = report.coverage(rules)
    assert "T1003.001" in cov["techniques"] and cov["unmapped_rules"] == []
    s = report.summarize(engine.run(rules, engine.read_events(EVENTS)))
    assert s["total_alerts"] == 5 and s["by_level"]["critical"] == 1


def test_read_events_json_array(tmp_path):
    p = tmp_path / "e.json"
    p.write_text(json.dumps([{"a": 1}]))
    assert list(engine.read_events(p)) == [{"a": 1}]


def test_cli(capsys):
    assert cli.main(["validate", str(RULES)]) == 0
    assert cli.main(["run", str(RULES), str(EVENTS), "--fail-on", "critical"]) == 2
    assert cli.main(["run", str(RULES), str(EVENTS), "--json"]) == 0
    out = capsys.readouterr().out
    assert '"total_alerts": 5' in out
    assert cli.main(["run", "nope/", str(EVENTS)]) == 1
