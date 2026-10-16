"""Unit-test harness for rules: each rule ships ``tests.match`` / ``tests.no_match``."""

from __future__ import annotations

from dataclasses import dataclass

from .rules import Rule


@dataclass
class TestResult:
    __test__ = False  # not a pytest class
    rule_id: str
    passed: int
    failures: list[str]

    @property
    def ok(self) -> bool:
        return not self.failures


def run_rule_tests(rule: Rule) -> TestResult:
    """Threshold rules are tested at the per-event predicate level."""
    failures, passed = [], 0
    cases = [(e, True) for e in rule.tests.get("match", [])] + [
        (e, False) for e in rule.tests.get("no_match", [])
    ]
    if not cases:
        failures.append("rule has no tests (add tests.match / tests.no_match)")
    for i, (event, expected) in enumerate(cases, 1):
        if rule.matches(event) == expected:
            passed += 1
        else:
            want = "match" if expected else "not match"
            failures.append(f"case {i}: expected to {want}: {event}")
    return TestResult(rule.id, passed, failures)
