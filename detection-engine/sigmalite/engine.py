"""Run rules over events and emit alerts."""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict
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

    def to_dict(self) -> dict:
        return asdict(self)


def read_jsonl(lines: Iterable[str]) -> Iterator[tuple[int, dict]]:
    """Yield (line_number, event); malformed lines raise ValueError with the line."""
    for n, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {n}: invalid JSON ({exc.msg})") from exc
        if not isinstance(ev, dict):
            raise ValueError(f"line {n}: event must be a JSON object")
        yield n, ev


def scan_events(rules: list[Rule], events: Iterable[tuple[int, dict]],
                min_level: str = "informational") -> list[Alert]:
    floor = LEVELS.index(min_level)
    active = [r for r in rules if LEVELS.index(r.level) >= floor]
    alerts = [Alert(r.id, r.title, r.level, r.techniques, n, ev)
              for n, ev in events for r in active if r.matches(ev)]
    return sorted(alerts, key=lambda a: (-LEVELS.index(a.level), a.line))
