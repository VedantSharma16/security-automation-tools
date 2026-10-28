"""Run rules over a stream of events and collect alerts."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from typing import Iterable, Iterator

from .rules import LEVELS, Rule


@dataclass
class Alert:
    rule_id: str
    title: str
    level: str
    techniques: list[str]
    tactics: list[str]
    line: int
    event: dict

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def read_jsonl(lines: Iterable[str]) -> Iterator[tuple[int, dict]]:
    """Yield (line_number, event); malformed lines raise ValueError with context."""
    for n, raw in enumerate(lines, 1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {n}: invalid JSON ({exc.msg})") from exc
        if not isinstance(event, dict):
            raise ValueError(f"line {n}: event must be a JSON object")
        yield n, event


class Engine:
    def __init__(self, rules: list[Rule], min_level: str = "informational"):
        if min_level not in LEVELS:
            raise ValueError(f"unknown level {min_level!r}")
        floor = LEVELS.index(min_level)
        self.rules = [r for r in rules if LEVELS.index(r.level) >= floor]

    def scan(self, events: Iterable[tuple[int, dict]]) -> list[Alert]:
        alerts = []
        for line, event in events:
            for rule in self.rules:
                if rule.matches(event):
                    alerts.append(Alert(rule.id, rule.title, rule.level,
                                        rule.techniques, rule.tactics, line, event))
        return alerts

    @staticmethod
    def summarize(alerts: list[Alert]) -> dict:
        return {
            "total": len(alerts),
            "by_level": dict(Counter(a.level for a in alerts)),
            "by_rule": dict(Counter(a.title for a in alerts)),
            "techniques": sorted({t for a in alerts for t in a.techniques}),
        }
