import json
from pathlib import Path

import pytest

from sigmalite.engine import Engine, read_events
from sigmalite.rules import RuleError, load_rules, parse_rule
from sigmalite.testing import run_rule_tests

ROOT = Path(__file__).parent.parent
RULES = ROOT / "rules"


def brute_rule(count=3, window="1m"):
    return parse_rule({
        "id": "T-1", "title": "bf", "level": "high",
        "detection": {"f": {"outcome": "failure"}, "condition": "f"},
        "threshold": {"count": count, "timeframe": window, "group_by": ["ip"]},
    })


def ev(sec, ip="1.1.1.1", outcome="failure"):
    return {"timestamp": f"2026-01-01T00:00:{sec:02d}Z", "ip": ip, "outcome": outcome}


def test_all_shipped_rules_pass_their_own_tests():
    for rule in load_rules(RULES):
        res = run_rule_tests(rule)
        assert res.ok, (rule.id, res.failures)


def test_threshold_fires_once_per_group_in_window():
    alerts = Engine([brute_rule()]).run([ev(1), ev(2), ev(3), ev(4), ev(5)])
    assert len(alerts) == 1
    assert alerts[0].group == {"ip": "1.1.1.1"} and alerts[0].matched_events == 3


def test_threshold_respects_window_and_groups():
    events = [ev(0), ev(30), ev(59, ip="2.2.2.2"), ev(5, ip="2.2.2.2")]
    events.sort(key=lambda e: e["timestamp"])
    assert Engine([brute_rule(3, "10s")]).run(events) == []
    assert Engine([brute_rule(2, "1m")]).run(events)  # both groups reach 2


def test_threshold_rearms_after_window_drains():
    events = [ev(0), ev(1), ev(2)] + [{"timestamp": "2026-01-01T00:05:00Z", "ip": "1.1.1.1", "outcome": "success"}]
    events += [{**ev(0), "timestamp": f"2026-01-01T00:10:0{i}Z"} for i in range(3)]
    assert len(Engine([brute_rule()]).run(events)) == 2


def test_sample_events_end_to_end():
    alerts = Engine(load_rules(RULES)).run(read_events((ROOT / "samples/events.jsonl").read_text().splitlines()))
    ids = {a.rule_id for a in alerts}
    assert ids == {"SL-001", "SL-002", "SL-003", "SL-004", "SL-005", "SL-006", "SL-007"}
    assert alerts[0].level == "critical"
    brute = [a for a in alerts if a.rule_id == "SL-006"]
    assert len(brute) == 1 and brute[0].group == {"src_ip": "203.0.113.50"}


def test_read_events_reports_line_numbers():
    with pytest.raises(ValueError, match="line 2"):
        list(read_events(['{"a":1}', "{oops"]))


@pytest.mark.parametrize("mutate", [
    lambda r: r.pop("id"),
    lambda r: r.update(level="severe"),
    lambda r: r["detection"].update(condition="missing"),
    lambda r: r.update(threshold={"count": 1, "timeframe": "5m"}),
    lambda r: r.update(threshold={"count": 3, "timeframe": "five"}),
])
def test_invalid_rules_rejected(mutate):
    rule = json.loads((RULES / "sl-001.json").read_text())
    mutate(rule)
    with pytest.raises(RuleError):
        parse_rule(rule)


def test_duplicate_ids_rejected(tmp_path):
    rule = (RULES / "sl-001.json").read_text()
    (tmp_path / "a.json").write_text(rule)
    (tmp_path / "b.json").write_text(rule)
    with pytest.raises(RuleError, match="duplicate"):
        load_rules(tmp_path)


def test_failing_rule_test_is_reported():
    rule = parse_rule({"id": "X", "title": "x", "level": "low",
                       "detection": {"s": {"a": "1"}, "condition": "s"},
                       "tests": {"match": [{"a": "2"}]}})
    res = run_rule_tests(rule)
    assert not res.ok and "case 1" in res.failures[0]
