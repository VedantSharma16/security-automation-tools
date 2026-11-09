"""Evaluate rules against an event stream."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

from .rule import LEVELS, Rule


@dataclass
class Match:
    rule: Rule
    event: Mapping[str, Any]
    line: int

    def to_dict(self) -> dict:
        return {"rule_id": self.rule.id, "title": self.rule.title, "level": self.rule.level,
                "techniques": self.rule.techniques, "tactics": self.rule.tactics,
                "line": self.line, "event": self.event}


def _logsource_ok(rule: Rule, event: Mapping[str, Any]) -> bool:
    """If an event carries a 'category' it must agree with the rule's logsource category."""
    want = rule.logsource.get("category")
    have = event.get("category")
    return not (want and have and str(want).lower() != str(have).lower())


class Engine:
    def __init__(self, rules: Iterable[Rule], min_level: str = "informational"):
        self.min_rank = LEVELS.index(min_level)
        self.rules = [r for r in rules if LEVELS.index(r.level) >= self.min_rank]

    def scan(self, events: Iterable[Mapping[str, Any]]) -> Iterator[Match]:
        for i, ev in enumerate(events, 1):
            for r in self.rules:
                if _logsource_ok(r, ev) and r.matches(ev):
                    yield Match(r, ev, i)


def read_events(path: str | Path) -> Iterator[dict]:
    """JSON Lines, or a single JSON array. Malformed lines raise ValueError with line number."""
    text = Path(path).read_text().strip()
    if text.startswith("["):
        yield from json.loads(text)
        return
    for n, line in enumerate(text.splitlines(), 1):
        if line.strip():
            try:
                yield json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"{path}:{n}: invalid JSON ({e.msg})") from e
