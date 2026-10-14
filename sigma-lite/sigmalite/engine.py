"""Evaluate events against compiled rules and summarise coverage."""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from typing import Iterable, Iterator

from .rules import LEVELS, Rule


@dataclass
class Match:
    rule: Rule
    event: dict
    line: int


def read_jsonl(lines: Iterable[str]) -> Iterator[tuple[int, dict]]:
    """Yield (line number, event). Malformed/non-object lines raise ValueError."""
    for n, raw in enumerate(lines, 1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            ev = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ValueError(f"line {n}: invalid JSON ({e.msg})") from e
        if not isinstance(ev, dict):
            raise ValueError(f"line {n}: event must be a JSON object")
        yield n, ev


def evaluate_events(rules: list[Rule], events: Iterable[tuple[int, dict]],
                    min_level: str = "informational") -> list[Match]:
    floor = LEVELS.index(min_level)
    active = [r for r in rules if LEVELS.index(r.level) >= floor]
    return [Match(r, ev, n) for n, ev in events for r in active if r.evaluate(ev)]


def summarize(matches: list[Match]) -> dict:
    by_level = Counter(m.rule.level for m in matches)
    by_rule = Counter(m.rule.title for m in matches)
    techniques = Counter(t for m in matches for t in m.rule.techniques)
    return {
        "total": len(matches),
        "by_level": {l: by_level[l] for l in reversed(LEVELS) if by_level[l]},
        "by_rule": dict(by_rule.most_common()),
        "techniques": dict(techniques.most_common()),
    }
