"""CI guard: the shipped rule pack must lint clean, be fully tested, and pass its tests."""

from pathlib import Path

from detlab.engine import load_events, scan
from detlab.rules import iter_rule_documents, lint_rule_data, load_rules
from detlab.testing import load_test_cases, run_suite

ROOT = Path(__file__).resolve().parent.parent


def test_rule_pack_lints_without_errors_or_warnings():
    for label, doc in iter_rule_documents([ROOT / "rules"]):
        assert lint_rule_data(doc) == [], label


def test_rule_pack_ids_are_unique():
    ids = [r.id for r in load_rules([ROOT / "rules"]).rules]
    assert len(ids) == len(set(ids))


def test_every_rule_has_passing_tests():
    loaded = load_rules([ROOT / "rules"])
    assert not loaded.errors
    suite = run_suite(loaded.rules, load_test_cases([ROOT / "rule_tests"]))
    failures = {r.rule_title: r.failure_messages() for r in suite.results if not r.passed}
    assert not failures
    assert not suite.untested_rules and not suite.orphan_tests


def test_incident_timeline_reconstructs_the_kill_chain():
    rules = load_rules([ROOT / "rules"]).rules
    events, errors = load_events(ROOT / "samples" / "incident_timeline.jsonl")
    assert not errors
    result = scan(rules, events)
    techniques = {t for a in result.alerts for t in a.techniques}
    assert {"T1566.001", "T1059.001", "T1105", "T1547.001", "T1053.005", "T1003.001", "T1490", "T1059.004"} <= techniques
    # benign noise in the sample (SCCM PowerShell, certutil hashing, OneDrive run key, nc port check) stays quiet
    flagged = {a.event_index for a in result.alerts}
    benign = [i for i, e in enumerate(events) if e.get("User") == "monitor" or "CcmExec" in e.get("ParentImage", "")
              or "-hashfile" in e.get("CommandLine", "") or "OneDrive" in e.get("TargetObject", "")]
    assert benign and not flagged & set(benign)
