"""Run rules over events and collect matches."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterable, Iterator

from .rules import LEVELS, Rule


@dataclass(frozen=True)
class Match:
    rule: Rule
    event: dict
    index: int  # zero-based position of the event in the stream

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule.id,
            "title": self.rule.title,
            "level": self.rule.level,
            "attack": self.rule.attack_techniques,
            "event_index": self.index,
            "event": self.event,
        }


def evaluate(rules: Iterable[Rule], event: dict) -> list[Rule]:
    return [r for r in rules if r.matches(event)]


def scan(rules: Iterable[Rule], events: Iterable[dict], min_level: str = "informational") -> Iterator[Match]:
    rules = [r for r in rules if LEVELS.index(r.level) >= LEVELS.index(min_level)]
    for i, event in enumerate(events):
        for rule in evaluate(rules, event):
            yield Match(rule, event, i)


def read_events(lines: Iterable[str]) -> Iterator[dict]:
    """Parse JSONL; also accepts a single JSON array on one logical document."""
    text = "".join(lines).strip()
    if text.startswith("["):
        yield from (e for e in json.loads(text) if isinstance(e, dict))
        return
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {n}: invalid JSON ({exc.msg})") from exc
        if isinstance(obj, dict):
            yield obj
