import json
from pathlib import Path

import pytest
from sigmalite.coverage import coverage
from sigmalite.engine import Engine, load_events
from sigmalite.rule import RuleError, load_rules, parse_rule

ROOT = Path(__file__).resolve().parent.parent
RULES, SAMPLES = ROOT / "rules", ROOT / "samples" / "events.jsonl"


def doc(**kw):
    base = {"title": "t", "detection": {"s": {"a": "1"}, "condition": "s"}}
    base.update(kw)
    return base


def test_parse_minimal_and_defaults():
    r = parse_rule(doc())
    assert r.level == "medium" and r.techniques == []


@pytest.mark.parametrize("bad", [
    {"detection": {"s": {"a": 1}, "condition": "s"}},
    {"title": "x"},
    {"title": "x", "detection": {"s": {"a": 1}}},
    {"title": "x", "level": "extreme", "detection": {"s": {"a": 1}, "condition": "s"}},
    {"title": "x", "detection": {"condition": "s"}},
    {"title": "x", "detection": {"s": {"a|nope": 1}, "condition": "s"}},
    {"title": "x", "detection": {"s": {"a": 1}, "condition": "missing"}},
])
def test_invalid_rules(bad):
    with pytest.raises(RuleError):
        parse_rule(bad)


def test_tags_split_into_techniques_and_tactics():
    r = parse_rule(doc(tags=["attack.execution", "attack.t1059.001", "attack.T1027"]))
    assert r.techniques == ["T1027", "T1059.001"] and r.tactics == ["execution"]


def test_shipped_rules_all_load():
    assert len(load_rules(RULES)) >= 5


def test_duplicate_ids_rejected(tmp_path):
    for n in "ab":
        (tmp_path / f"{n}.yml").write_text("id: same\ntitle: t\ndetection:\n  s: {a: 1}\n  condition: s\n")
    with pytest.raises(RuleError, match="duplicate"):
        load_rules(tmp_path)


def test_sample_events_expected_detections():
    matches = list(Engine(load_rules(RULES)).run(load_events(SAMPLES)))
    got = {(m.index, m.rule.id) for m in matches}
    assert (0, "win-ps-encoded") in got
    assert (0, "win-office-shell") in got
    assert (1, "win-lsass-dump") in got
    assert (2, "win-schtask-persist") in got
    assert (5, "net-suspicious-egress") in got
    # negatives: Microsoft-path task, benign explorer, internal destination
    assert not {3, 4, 6} & {i for i, _ in got}


def test_min_level_filters():
    ids = {m.rule.id for m in Engine(load_rules(RULES), "critical").run(load_events(SAMPLES))}
    assert ids == {"win-lsass-dump"}


def test_logsource_mismatch_skipped():
    r = parse_rule(doc(logsource={"product": "linux"}))
    assert not Engine([r]).match_event({"a": "1", "_product": "windows"})
    assert Engine([r]).match_event({"a": "1", "_product": "linux"})
    assert Engine([r]).match_event({"a": "1"})  # unlabeled still evaluated


def test_load_events_formats_and_errors(tmp_path):
    arr = tmp_path / "a.json"
    arr.write_text(json.dumps([{"x": 1}, {"x": 2}]))
    assert len(list(load_events(arr))) == 2
    bad = tmp_path / "b.jsonl"
    bad.write_text('{"x":1}\nnot json\n')
    with pytest.raises(ValueError, match=":2:"):
        list(load_events(bad))


def test_coverage_gaps():
    rep = coverage(load_rules(RULES), {"T1059", "T1003", "T1486"})
    assert rep["target_gaps"] == ["T1486"]
    assert rep["target_coverage_pct"] == 66.7
