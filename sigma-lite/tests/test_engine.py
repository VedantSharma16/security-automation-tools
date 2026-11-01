import json
from pathlib import Path

import pytest
from sigmalite.cli import main
from sigmalite.engine import coverage, read_events, scan, self_test
from sigmalite.rule import RuleError, from_dict, load_rules

ROOT = Path(__file__).resolve().parent.parent
RULES, SAMPLES = ROOT / "rules", ROOT / "samples" / "events.jsonl"


def mk(**over):
    d = {"title": "t", "id": "x1", "detection": {"s": {"a": 1}, "condition": "s"}}
    d.update(over)
    return d


def test_bundled_rules_pass_their_own_tests():
    assert self_test(load_rules(RULES)) == []


def test_scan_sample_events():
    alerts = scan(load_rules(RULES), read_events(SAMPLES))
    ids = {(a.line, a.rule_id) for a in alerts}
    assert {(1, "sl-0003"), (2, "sl-0001"), (4, "sl-0002"), (5, "sl-0004")} <= ids
    assert all(a.line not in (3, 6) for a in alerts)
    assert alerts[0].level == "critical"  # sorted by severity


def test_min_level_filter():
    alerts = scan(load_rules(RULES), read_events(SAMPLES), "critical")
    assert {a.rule_id for a in alerts} == {"sl-0002"}


def test_self_test_detects_false_positive_and_missing_tests():
    bad = from_dict(mk(tests={"match": [{"a": 1}], "no_match": [{"a": 1}]}))
    assert any("false positive" in f for f in self_test([bad]))
    assert any("no 'match'" in f for f in self_test([from_dict(mk())]))


@pytest.mark.parametrize("doc", [
    mk(level="apocalyptic"),
    mk(detection={"s": {"a": 1}, "condition": "nope"}),
    mk(detection={"s": {"a": 1}, "condition": "s and"}),
    mk(detection={"condition": "s"}),
    mk(detection={"s": {"a": 1}}),
])
def test_invalid_rules_rejected(doc):
    with pytest.raises(RuleError):
        from_dict(doc)


def test_duplicate_ids(tmp_path):
    for n in "ab":
        (tmp_path / f"{n}.yml").write_text(
            "title: t\nid: dup\ndetection:\n  s: {a: 1}\n  condition: s\n")
    with pytest.raises(RuleError, match="duplicate"):
        load_rules(tmp_path)


def test_coverage():
    cov = coverage(load_rules(RULES))
    assert "T1059.001" in cov["techniques"] and cov["rules"] == 5
    assert cov["untagged_rules"] == []


def test_bad_jsonl(tmp_path):
    p = tmp_path / "e.jsonl"
    p.write_text('{"a":1}\nnot json\n')
    with pytest.raises(ValueError, match=":2:"):
        list(read_events(p))


def test_cli(capsys):
    assert main(["scan", str(RULES), str(SAMPLES), "--json"]) == 1
    assert len(json.loads(capsys.readouterr().out)) >= 4
    assert main(["test", str(RULES)]) == 0
    assert main(["coverage", str(RULES)]) == 0
    assert main(["scan", str(RULES), "/nonexistent"]) == 2
