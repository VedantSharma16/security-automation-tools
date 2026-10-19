"""Run rules over events and aggregate results."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterable, Iterator

from .rule import LEVELS, Rule


@dataclass
class Match:
    rule: Rule
    line: int
    event: dict


def read_jsonl(lines: Iterable[str]) -> Iterator[tuple[int, dict]]:
    for n, raw in enumerate(lines, 1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {n}: invalid JSON ({exc.msg})") from exc
        if isinstance(obj, dict):
            yield n, obj


def scan_events(rules: list[Rule], events: Iterable[tuple[int, dict]], min_level: str = "informational") -> list[Match]:
    floor = LEVELS.index(min_level)
    active = [r for r in rules if LEVELS.index(r.level) >= floor]
    return [Match(r, n, ev) for n, ev in events for r in active if r.matches(ev)]


def coverage(rules: list[Rule]) -> dict[str, list[str]]:
    """Map ATT&CK technique ID -> titles of rules that cover it."""
    out: dict[str, list[str]] = {}
    for r in rules:
        for t in r.techniques:
            out.setdefault(t, []).append(r.title)
    return dict(sorted(out.items()))
