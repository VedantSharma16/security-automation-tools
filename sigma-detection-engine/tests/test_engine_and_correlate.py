import json
from pathlib import Path

import pytest

from sigmalite.correlate import correlate, parse_ts
from sigmalite.engine import Alert, Engine, load_field_map, read_events
from sigmalite.rule import rule_from_dict

ROOT = Path(__file__).resolve().parent.parent


def rule(title, level, tags, sel):
    return rule_from_dict({
        "title": title, "level": level, "tags": tags,
        "logsource": {"product": "windows"},
        "detection": {"sel": sel, "condition": "sel"},
    }).compile()


RULES = [
    rule("Exec", "medium", ["attack.execution"], {"Image|endswith": "\\powershell.exe"}),
    rule("Cred", "high", ["attack.credential_access"], {"CommandLine|contains": "lsass"}),
    rule("Impact", "high", ["attack.impact"], {"CommandLine|contains": "delete shadows"}),
    rule("Info", "informational", [], {"Image|endswith": "\\notepad.exe"}),
]


def test_engine_produces_alerts_with_context():
    events = [{"Computer": "h1", "UtcTime": "2026-01-01 10:00:00", "Image": "C:\\powershell.exe",
               "CommandLine": "powershell dump lsass"}]
    alerts = Engine(RULES).scan(events)
    assert [a.rule_title for a in alerts] == ["Exec", "Cred"]
    assert alerts[0].host == "h1"
    assert alerts[0].context["CommandLine"] == "powershell dump lsass"


def test_min_level_filters_rules():
    engine = Engine(RULES, min_level="high")
    assert {r.title for r in engine.rules} == {"Cred", "Impact"}


def test_logsource_mismatch_skips_rule():
    ev = {"logsource": {"product": "linux"}, "Image": "/x/powershell.exe"}
    assert Engine(RULES).scan([ev]) == []


def test_field_map_with_ecs_sample():
    fm = load_field_map(ROOT / "config" / "ecs_field_map.yml")
    events = list(read_events(ROOT / "samples" / "ecs_events.json"))
    from sigmalite.rule import load_rules
    alerts = Engine(load_rules(ROOT / "rules", fm), fm).scan(events)
    assert {a.rule_title for a in alerts} == {
        "Certutil Used to Download or Decode a Payload", "Volume Shadow Copy Deletion"}
    assert all(a.host == "WS-FIN-07" for a in alerts)


def test_read_events_jsonl_skips_comments_and_reports_bad_lines(tmp_path):
    p = tmp_path / "e.jsonl"
    p.write_text('# comment\n{"a": 1}\n\n{"a": 2}\n')
    assert [e["a"] for e in read_events(p)] == [1, 2]
    p.write_text('{"a": 1}\n{oops}\n')
    with pytest.raises(ValueError, match=":2:"):
        list(read_events(p))


def test_read_events_json_array(tmp_path):
    p = tmp_path / "e.json"
    p.write_text(json.dumps([{"a": 1}]))
    assert list(read_events(p)) == [{"a": 1}]


# --------------------------------------------------------------------- correlation


def alert(title, level, tactics, host, ts):
    return Alert(rule_id=title, rule_title=title, level=level, tags=[], techniques=[],
                 tactics=tactics, host=host, timestamp=ts, event_index=0)


def test_parse_ts_formats():
    assert parse_ts("2026-11-16 09:12:09.204").minute == 12
    assert parse_ts("2026-11-16T09:12:09Z").tzinfo is not None
    assert parse_ts("garbage") is None
    assert parse_ts(None) is None


def test_correlate_splits_on_window_and_host():
    alerts = [
        alert("a", "low", ["discovery"], "h1", "2026-01-01 10:00:00"),
        alert("b", "low", ["discovery"], "h1", "2026-01-01 10:20:00"),
        alert("c", "low", ["discovery"], "h1", "2026-01-01 11:30:00"),  # > 30m gap
        alert("d", "low", ["discovery"], "h2", "2026-01-01 10:05:00"),
    ]
    incidents = correlate(alerts, window_minutes=30)
    sizes = sorted((i.host, len(i.alerts)) for i in incidents)
    assert sizes == [("h1", 1), ("h1", 2), ("h2", 1)]


def test_multi_stage_incident_is_escalated_and_ordered_by_kill_chain():
    alerts = [
        alert("imp", "high", ["impact"], "h1", "2026-01-01 10:10:00"),
        alert("exe", "medium", ["execution"], "h1", "2026-01-01 10:00:00"),
        alert("cred", "medium", ["credential_access"], "h1", "2026-01-01 10:05:00"),
        alert("solo", "high", ["execution"], "h2", "2026-01-01 10:00:00"),
    ]
    incidents = correlate(alerts)
    top = incidents[0]
    assert top.host == "h1" and top.multi_stage
    assert top.level == "critical"  # high escalated one step
    assert top.tactics == ["execution", "credential_access", "impact"]
    assert [a.rule_title for a in top.alerts] == ["exe", "cred", "imp"]  # time-ordered
    assert incidents[1].level == "high" and not incidents[1].multi_stage


def test_escalation_caps_at_critical_and_untimed_alerts_grouped():
    alerts = [alert(t, "critical", [t], "h", None) for t in ("execution", "persistence", "impact")]
    (inc,) = correlate(alerts)
    assert inc.level == "critical" and inc.start is None and len(inc.alerts) == 3
