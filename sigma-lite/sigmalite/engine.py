"""Evaluation engine: run rules over a stream of events."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from .condition import evaluate
from .rule import LEVELS, Rule


@dataclass
class Match:
    rule: Rule
    event: dict
    index: int

    def to_dict(self) -> dict:
        return {"rule_id": self.rule.id, "title": self.rule.title, "level": self.rule.level,
                "techniques": self.rule.techniques, "tactics": self.rule.tactics,
                "event_index": self.index, "event": self.event}


def _logsource_ok(rule: Rule, event: dict) -> bool:
    """Optional coarse filter: logsource.category/product/service compared to same-named event keys
    only when the event actually carries them (so unlabeled logs are still evaluated)."""
    for key in ("category", "product", "service"):
        want, have = rule.logsource.get(key), event.get(f"_{key}")
        if want and have and str(want).lower() != str(have).lower():
            return False
    return True


class _LazyResults(dict):
    """Evaluate each selection at most once per (rule, event), and only if the condition needs it."""

    def __init__(self, rule: Rule, event: dict):
        super().__init__()
        self._rule, self._event, self._memo = rule, event, {}

    def __getitem__(self, name):
        return lambda: self._memo[name] if name in self._memo else self._memo.setdefault(
            name, self._rule.selections[name](self._event))


class Engine:
    def __init__(self, rules: Iterable[Rule], min_level: str = "informational"):
        self.min_rank = LEVELS.index(min_level)
        self.rules = [r for r in rules if LEVELS.index(r.level) >= self.min_rank]

    def match_event(self, event: dict, index: int = 0) -> list[Match]:
        out = []
        for rule in self.rules:
            if not _logsource_ok(rule, event):
                continue
            results = _LazyResults(rule, event)
            if evaluate(rule.ast, results):
                out.append(Match(rule, event, index))
        return out

    def run(self, events: Iterable[dict]) -> Iterator[Match]:
        for i, ev in enumerate(events):
            yield from self.match_event(ev, i)


def load_events(path: str | Path) -> Iterator[dict]:
    """Read events from JSON Lines or a JSON array. Malformed lines raise ValueError with line number."""
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if text.lstrip().startswith("["):
        data = json.loads(text)
        yield from (e for e in data if isinstance(e, dict))
        return
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{p}:{n}: invalid JSON ({exc.msg})") from exc
        if isinstance(obj, dict):
            yield obj
