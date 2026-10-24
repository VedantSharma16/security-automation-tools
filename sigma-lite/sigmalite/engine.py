"""Run rules over events and run rule self-tests."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterable, Iterator

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


class Engine:
    def __init__(self, rules: list[Rule]):
        self.rules = rules

    def scan(self, events: Iterable[dict], min_level: str = "informational") -> Iterator[Alert]:
        floor = LEVELS.index(min_level)
        for n, event in enumerate(events, 1):
            for rule in self.rules:
                if LEVELS.index(rule.level) >= floor and rule.matches(event):
                    yield Alert(rule.id, rule.title, rule.level, rule.techniques, n, event)

    def self_test(self) -> list[str]:
        """Check each rule's embedded ``tests`` block. Returns failure messages."""
        failures = []
        for rule in self.rules:
            pos, neg = rule.tests.get("match", []), rule.tests.get("no_match", [])
            if not pos or not neg:
                failures.append(f"{rule.id}: needs at least one match and one no_match test")
            failures += [f"{rule.id}: expected match, got none for {e}" for e in pos if not rule.matches(e)]
            failures += [f"{rule.id}: unexpected match for {e}" for e in neg if rule.matches(e)]
        return failures


def read_events(lines: Iterable[str]) -> Iterator[dict]:
    for n, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {n}: invalid JSON ({exc.msg})") from exc
        if not isinstance(obj, dict):
            raise ValueError(f"line {n}: event must be a JSON object")
        yield obj


def coverage(rules: list[Rule]) -> dict[str, list[str]]:
    """Map ATT&CK technique id -> rule ids covering it."""
    cov: dict[str, list[str]] = {}
    for r in rules:
        for t in r.techniques:
            cov.setdefault(t, []).append(r.id)
    return dict(sorted(cov.items()))
