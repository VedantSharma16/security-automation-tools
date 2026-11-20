"""Detection-as-code: unit tests for detection rules.

Each test file targets one rule by id and lists events that must or must
not fire it::

    rule_id: 5b2c1e8a-...
    cases:
      - name: encoded command via -enc
        expect: match
        event: {Image: 'C:\\...\\powershell.exe', CommandLine: 'powershell -enc SQBFAFgA'}
      - name: admin running a signed script
        expect: no_match
        event: {...}

Running the suite catches regressions when a rule is tuned (a new filter
that silently kills true positives) and documents intent for reviewers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

from .rule import Rule

__all__ = ["CaseResult", "TestReport", "TestSuiteError", "run_rule_tests"]

_EXPECT = {"match": True, "no_match": False}


class TestSuiteError(ValueError):
    """Raised for malformed test files."""

    __test__ = False  # not a pytest test class


@dataclass
class CaseResult:
    rule_id: str
    rule_title: str
    name: str
    expected: bool
    actual: bool
    source: str

    @property
    def passed(self) -> bool:
        return self.expected == self.actual


@dataclass
class TestReport:
    __test__ = False

    results: list[CaseResult] = field(default_factory=list)
    untested_rules: list[Rule] = field(default_factory=list)
    rules_missing_negative: list[Rule] = field(default_factory=list)
    orphan_files: list[str] = field(default_factory=list)

    @property
    def failures(self) -> list[CaseResult]:
        return [r for r in self.results if not r.passed]

    @property
    def ok(self) -> bool:
        return not self.failures and not self.orphan_files

    def coverage(self, total_rules: int) -> float:
        if total_rules == 0:
            return 0.0
        return (total_rules - len(self.untested_rules)) / total_rules


def _test_files(paths: Iterable[str | Path]) -> list[Path]:
    files: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            files.extend(sorted(x for x in p.rglob("*") if x.suffix in (".yml", ".yaml")))
        elif p.exists():
            files.append(p)
    return files


def _load_suite(path: Path) -> tuple[str, list[dict[str, Any]]]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or "rule_id" not in doc or "cases" not in doc:
        raise TestSuiteError(f"{path}: test file needs 'rule_id' and 'cases'")
    cases = doc["cases"]
    if not isinstance(cases, list) or not cases:
        raise TestSuiteError(f"{path}: 'cases' must be a non-empty list")
    for i, case in enumerate(cases):
        if not isinstance(case, dict) or case.get("expect") not in _EXPECT or not isinstance(case.get("event"), dict):
            raise TestSuiteError(
                f"{path}: case #{i + 1} needs 'expect' (match|no_match) and an 'event' mapping"
            )
    return str(doc["rule_id"]), cases


def run_rule_tests(rules: list[Rule], test_paths: Iterable[str | Path]) -> TestReport:
    """Run every test case against its target rule."""
    by_id = {r.id: r for r in rules}
    report = TestReport()
    tested: set[str] = set()
    has_negative: set[str] = set()

    for path in _test_files(test_paths):
        rule_id, cases = _load_suite(path)
        rule = by_id.get(rule_id)
        if rule is None:
            report.orphan_files.append(f"{path} (unknown rule_id {rule_id})")
            continue
        tested.add(rule_id)
        for i, case in enumerate(cases):
            expected = _EXPECT[case["expect"]]
            if not expected:
                has_negative.add(rule_id)
            report.results.append(
                CaseResult(
                    rule_id=rule.id,
                    rule_title=rule.title,
                    name=str(case.get("name") or f"case {i + 1}"),
                    expected=expected,
                    actual=rule.matches(case["event"]),
                    source=str(path),
                )
            )

    report.untested_rules = [r for r in rules if r.id not in tested]
    report.rules_missing_negative = [r for r in rules if r.id in tested and r.id not in has_negative]
    return report
