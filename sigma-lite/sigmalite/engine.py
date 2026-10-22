"""Run rules over events and collect matches."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterable, Iterator

from .rule import LEVELS, Rule


@dataclass
class Match:
    rule: Rule
    event: dict
    line: int  # 1-based event index

    def to_dict(self) -> dict:
        return {"rule_id": self.rule.id, "title": self.rule.title, "level": self.rule.level,
                "techniques": self.rule.techniques, "tactics": self.rule.tactics,
                "line": self.line, "event": self.event}


def read_events(lines: Iterable[str]) -> Iterator[dict]:
    """Parse JSONL (or a single JSON array); non-object lines raise ValueError."""
    text = "\n".join(lines) if not isinstance(lines, str) else lines
    stripped = text.lstrip()
    if stripped.startswith("["):
        data = json.loads(stripped)
        if not all(isinstance(e, dict) for e in data):
            raise ValueError("JSON array must contain only objects")
        yield from data
        return
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {n}: invalid JSON: {exc}") from exc
        if not isinstance(obj, dict):
            raise ValueError(f"line {n}: expected a JSON object")
        yield obj


def evaluate_events(rules: list[Rule], events: Iterable[dict],
                    min_level: str = "informational") -> list[Match]:
    floor = LEVELS.index(min_level)
    active = [r for r in rules if LEVELS.index(r.level) >= floor]
    matches = []
    for idx, event in enumerate(events, 1):
        for rule in active:
            if rule.matches(event):
                matches.append(Match(rule, event, idx))
    return matches
