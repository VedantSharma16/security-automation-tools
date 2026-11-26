import json

from detlab.engine import load_events, logsource_applies, scan
from detlab.rules import compile_rule


def rule(level="high", logsource=None, status="test", title="r"):
    return compile_rule(
        {
            "title": title,
            "id": title,
            "level": level,
            "status": status,
            "logsource": logsource or {"product": "windows", "category": "process_creation"},
            "tags": ["attack.execution", "attack.t1059.001"],
            "detection": {"sel": {"Image|endswith": "\\powershell.exe"}, "condition": "sel"},
        }
    )


PS = {"Image": "C:\\x\\powershell.exe"}


def test_scan_produces_alerts_with_attack_context():
    result = scan([rule()], [PS, {"Image": "notepad.exe"}])
    assert result.events_scanned == 2
    assert len(result.alerts) == 1
    alert = result.alerts[0]
    assert alert.event_index == 0 and alert.techniques == ["T1059.001"] and alert.matched_selections == ["sel"]
    assert result.by_level() == {"high": 1}


def test_min_level_and_deprecated_rules_are_skipped():
    rules = [rule(level="low", title="low"), rule(level="critical", title="crit"), rule(status="deprecated", title="old")]
    result = scan(rules, [PS], min_level="high")
    assert [a.rule_title for a in result.alerts] == ["crit"]
    assert result.rules_loaded == 1


def test_by_rule_orders_by_severity_then_count():
    rules = [rule(level="medium", title="m"), rule(level="critical", title="c")]
    result = scan(rules, [PS, PS])
    assert result.by_rule() == [("c", "critical", 2), ("m", "medium", 2)]


def test_logsource_filtering():
    win = rule()
    assert logsource_applies(win, {})
    assert logsource_applies(win, {"_logsource": {"product": "Windows"}})
    assert not logsource_applies(win, {"_logsource": {"product": "linux"}})
    assert not logsource_applies(win, {"_logsource": {"category": "registry_set"}})
    assert scan([win], [{**PS, "_logsource": {"product": "linux"}}]).alerts == []


def test_load_events_jsonl_with_bad_lines(tmp_path):
    path = tmp_path / "e.jsonl"
    path.write_text('{"a": 1}\n\nnot json\n[1,2]\n{"b": 2}\n')
    events, errors = load_events(path)
    assert events == [{"a": 1}, {"b": 2}]
    assert len(errors) == 2 and errors[0].startswith("line 3")


def test_load_events_json_array(tmp_path):
    path = tmp_path / "e.json"
    path.write_text(json.dumps([{"a": 1}, 5]))
    events, errors = load_events(path)
    assert events == [{"a": 1}] and errors == ["item 1: not a JSON object"]


def test_to_dict_is_json_serialisable():
    assert json.loads(json.dumps(scan([rule()], [PS]).to_dict()))["alert_count"] == 1
