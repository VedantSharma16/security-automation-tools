"""Run rules against events and collect alerts."""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
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


def read_events(path: str | Path) -> Iterator[tuple[int, dict]]:
    """Yield (line_number, event) from a JSONL file; malformed lines are skipped."""
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(ev, dict):
                yield n, ev


def scan(rules: Iterable[Rule], events: Iterable[tuple[int, dict]], min_level: str = "informational") -> list[Alert]:
    floor = LEVELS.index(min_level)
    active = [r for r in rules if LEVELS.index(r.level) >= floor]
    alerts = []
    for line, ev in events:
        for r in active:
            if r.matches(ev):
                alerts.append(Alert(r.id, r.title, r.level, r.techniques, line, ev))
    return alerts


def summarize(alerts: list[Alert]) -> dict:
    by_rule: dict[str, int] = defaultdict(int)
    by_level: dict[str, int] = defaultdict(int)
    for a in alerts:
        by_rule[a.title] += 1
        by_level[a.level] += 1
    return {"total": len(alerts), "by_level": dict(by_level), "by_rule": dict(by_rule)}
