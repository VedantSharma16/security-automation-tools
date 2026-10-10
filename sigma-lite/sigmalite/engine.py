"""Evaluate Sigma rules against event streams."""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, Iterator

from .condition import parse
from .matcher import match_selection
from .rule import Rule


@dataclass
class Match:
    rule_title: str
    rule_id: str
    level: str
    techniques: list[str]
    event_index: int
    event: dict

    def to_dict(self) -> dict:
        return asdict(self)


class CompiledRule:
    def __init__(self, rule: Rule):
        self.rule = rule
        self._cond = parse(rule.condition, list(rule.detection))

    def matches(self, event: dict) -> bool:
        results = {n: match_selection(event, sel) for n, sel in self.rule.detection.items()}
        return self._cond(results)


class Engine:
    def __init__(self, rules: Iterable[Rule]):
        self.compiled = [CompiledRule(r) for r in rules]

    def scan(self, events: Iterable[dict]) -> Iterator[Match]:
        for idx, event in enumerate(events):
            for c in self.compiled:
                if c.matches(event):
                    r = c.rule
                    yield Match(r.title, r.id, r.level, r.attack_techniques, idx, event)


def read_events(path: str | Path) -> Iterator[dict]:
    """Read JSON-lines (or a single JSON array) of events."""
    text = Path(path).read_text(encoding="utf-8").strip()
    if text.startswith("["):
        data = json.loads(text)
        for ev in data:
            yield ev
        return
    for no, line in enumerate(text.splitlines(), 1):
        if line.strip():
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{no}: invalid JSON ({exc.msg})") from exc
