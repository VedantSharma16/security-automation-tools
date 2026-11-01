"""Run rules over events, self-test rules, and report ATT&CK coverage."""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from .matcher import matches
from .rule import LEVELS, Rule


@dataclass
class Alert:
    rule_id: str
    title: str
    level: str
    techniques: list[str]
    line: int
    event: dict

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def read_events(path: str | Path) -> Iterator[tuple[int, dict]]:
    """Yield (line_number, event) from JSONL; malformed lines raise ValueError."""
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"{path}:{n}: invalid JSON: {e}") from e
            if not isinstance(ev, dict):
                raise ValueError(f"{path}:{n}: event must be an object")
            yield n, ev


def scan(rules: list[Rule], events: Iterable[tuple[int, dict]], min_level: str = "informational") -> list[Alert]:
    floor = LEVELS.index(min_level)
    active = [r for r in rules if LEVELS.index(r.level) >= floor]
    alerts = []
    for line, ev in events:
        for r in active:
            if matches(r, ev):
                alerts.append(Alert(r.id, r.title, r.level, r.techniques, line, ev))
    alerts.sort(key=lambda a: (-LEVELS.index(a.level), a.line))
    return alerts


def self_test(rules: list[Rule]) -> list[str]:
    """Run each rule's embedded tests; return failure messages (empty == pass).

    A rule with no positive test case is itself reported, since an untested
    detection is a liability.
    """
    failures = []
    for r in rules:
        if not r.tests["match"]:
            failures.append(f"{r.id}: no 'match' test case defined")
        for i, ev in enumerate(r.tests["match"]):
            if not matches(r, ev):
                failures.append(f"{r.id}: match case #{i} did not fire")
        for i, ev in enumerate(r.tests["no_match"]):
            if matches(r, ev):
                failures.append(f"{r.id}: no_match case #{i} fired (false positive)")
    return failures


def coverage(rules: list[Rule]) -> dict:
    by_tech: dict[str, list[str]] = defaultdict(list)
    by_tactic: dict[str, int] = defaultdict(int)
    for r in rules:
        for t in r.techniques:
            by_tech[t].append(r.id)
        for t in r.tactics:
            by_tactic[t] += 1
    untagged = [r.id for r in rules if not r.techniques]
    return {
        "rules": len(rules),
        "techniques": {k: sorted(v) for k, v in sorted(by_tech.items())},
        "tactics": dict(sorted(by_tactic.items())),
        "untagged_rules": untagged,
    }
