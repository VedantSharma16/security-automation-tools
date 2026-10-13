"""Run rules over an event stream and aggregate the results."""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

from .rules import LEVELS, Rule


@dataclass
class Alert:
    rule_id: str
    title: str
    level: str
    techniques: list[str]
    line: int
    event: dict


@dataclass
class ScanResult:
    events_scanned: int = 0
    skipped_lines: int = 0
    alerts: list[Alert] = field(default_factory=list)

    def by_rule(self) -> Counter:
        return Counter(a.rule_id for a in self.alerts)

    def by_technique(self) -> Counter:
        return Counter(t for a in self.alerts for t in a.techniques)

    def max_level(self) -> str | None:
        if not self.alerts:
            return None
        return max((a.level for a in self.alerts), key=LEVELS.index)


def read_events(path: str | Path) -> Iterator[tuple[int, dict | None]]:
    """Yield ``(line_number, event)``; malformed lines yield ``None``."""
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                yield n, None
                continue
            yield n, ev if isinstance(ev, dict) else None


def scan(rules: list[Rule], events: Iterable[tuple[int, dict | None]]) -> ScanResult:
    res = ScanResult()
    for line, ev in events:
        if ev is None:
            res.skipped_lines += 1
            continue
        res.events_scanned += 1
        for r in rules:
            if r.matches(ev):
                res.alerts.append(Alert(r.id, r.title, r.level, r.attack_techniques, line, ev))
    return res
