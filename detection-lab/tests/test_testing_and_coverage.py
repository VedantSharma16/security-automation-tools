from detlab.coverage import build_coverage
from detlab.rules import compile_rule
from detlab.testing import RuleTestCase, evaluate_case, run_suite


def make(rule_id, techs, tactics=("execution",), status="test"):
    return compile_rule(
        {
            "title": f"rule {rule_id}",
            "id": rule_id,
            "status": status,
            "tags": [f"attack.{t}" for t in tactics] + [f"attack.{t.lower()}" for t in techs],
            "detection": {"sel": {"CommandLine|contains": "evil"}, "condition": "sel"},
        }
    )


def test_evaluate_case_reports_misses_and_false_positives():
    case = RuleTestCase("a", [{"CommandLine": "evil"}, {"CommandLine": "good"}], [{"CommandLine": "more evil"}])
    res = evaluate_case(make("a", ["T1059"]), case)
    assert res.missed_positives == [1] and res.false_positives == [0] and not res.passed
    assert "did NOT match true_positives[1]" in res.failure_messages()


def test_rule_without_positive_samples_fails():
    res = evaluate_case(make("a", ["T1059"]), RuleTestCase("a", [], []))
    assert not res.passed


def test_run_suite_tracks_untested_and_orphans():
    rules = [make("a", ["T1059"]), make("b", ["T1105"])]
    cases = [RuleTestCase("a", [{"CommandLine": "evil"}], []), RuleTestCase("zzz", [{}], [], source="t.yml")]
    suite = run_suite(rules, cases)
    assert [r.id for r in suite.untested_rules] == ["b"]
    assert suite.orphan_tests and not suite.passed
    assert suite.coverage_pct == 50.0


def test_coverage_uses_reference_tactics_and_reports_gaps():
    ref = {
        "T1059.001": {"name": "PowerShell", "tactics": ["execution"]},
        "T1053.005": {"name": "Scheduled Task", "tactics": ["execution", "persistence"]},
        "T1490": {"name": "Inhibit System Recovery", "tactics": ["impact"]},
    }
    rules = [make("a", ["T1053.005"]), make("b", ["T9999"], tactics=("collection",)), make("c", ["T1490"], status="deprecated")]
    report = build_coverage(rules, ref)
    assert report.by_tactic == {"execution": ["T1053.005"], "persistence": ["T1053.005"], "collection": ["T9999"]}
    assert report.gaps == {"execution": ["T1059.001"], "impact": ["T1490"]}
    assert round(report.reference_coverage_pct) == 33


def test_default_reference_loads():
    report = build_coverage([make("a", ["T1059.001"])])
    assert "T1059.001" in report.covered and report.gaps
