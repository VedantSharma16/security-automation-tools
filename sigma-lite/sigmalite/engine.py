"""Run rules over a stream of events."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from .rule import LEVELS, Rule


@dataclass
class Match:
    rule: Rule
    event: dict
    line: int


class Engine:
    def __init__(self, rules: list[Rule], min_level: str = "informational"):
        self.rules = [r for r in rules if LEVELS.index(r.level) >= LEVELS.index(min_level)]

    def scan(self, events: Iterable[dict]) -> Iterator[Match]:
        for n, event in enumerate(events, 1):
            for rule in self.rules:
                if rule.matches(event):
                    yield Match(rule, event, n)


def read_events(path: str | Path) -> Iterator[dict]:
    """Read events from NDJSON or a JSON array; skips blank lines."""
    text = Path(path).read_text(encoding="utf-8").strip()
    if text.startswith("["):
        yield from (e for e in json.loads(text) if isinstance(e, dict))
        return
    for i, line in enumerate(text.splitlines(), 1):
        if line.strip():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"{path}:{i}: invalid JSON ({e.msg})") from e
            if isinstance(obj, dict):
                yield obj
