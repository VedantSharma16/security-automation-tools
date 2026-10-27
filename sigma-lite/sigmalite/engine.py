from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterable, Iterator

from .rules import LEVELS, Rule


@dataclass
class Match:
    rule: Rule
    event: dict
    line: int


def read_events(lines: Iterable[str]) -> Iterator[tuple[int, dict]]:
    """Yield (line_no, event) from JSONL, skipping blank/malformed lines."""
    for n, raw in enumerate(lines, 1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            ev = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(ev, dict):
            yield n, ev


def scan(events: Iterable[tuple[int, dict]], rules: list[Rule], min_level: str = "informational") -> list[Match]:
    floor = LEVELS.index(min_level)
    active = [r for r in rules if LEVELS.index(r.level) >= floor]
    return [Match(r, ev, n) for n, ev in events for r in active if r.evaluate(ev)]


def coverage(rules: list[Rule]) -> dict[str, list[str]]:
    """ATT&CK technique -> rule ids."""
    out: dict[str, list[str]] = {}
    for r in rules:
        for t in r.techniques:
            out.setdefault(t, []).append(r.id)
    return dict(sorted(out.items()))
