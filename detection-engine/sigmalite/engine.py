"""Evaluation engine: single-event matches and sliding-window thresholds."""

from __future__ import annotations

import json
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Iterator

from .matcher import get_field
from .rules import LEVELS, Rule


@dataclass
class Alert:
    rule_id: str
    title: str
    level: str
    techniques: list[str]
    tactics: list[str]
    timestamp: str | None
    group: dict = field(default_factory=dict)
    matched_events: int = 1
    sample: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def parse_timestamp(value) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def read_events(lines: Iterable[str]) -> Iterator[dict]:
    """Parse JSONL, skipping blank lines; raises ValueError with line number."""
    for n, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {n}: invalid JSON ({exc.msg})") from exc
        if isinstance(obj, dict):
            yield obj


class Engine:
    def __init__(self, rules: list[Rule], time_field: str = "timestamp"):
        self.rules = rules
        self.time_field = time_field

    def run(self, events: Iterable[dict]) -> list[Alert]:
        windows: dict[tuple, deque] = defaultdict(deque)
        fired: set[tuple] = set()
        alerts: list[Alert] = []
        for index, event in enumerate(events):
            ts = parse_timestamp(get_field(event, self.time_field))
            for rule in self.rules:
                if not rule.matches(event):
                    continue
                if rule.threshold is None:
                    alerts.append(self._alert(rule, event, 1, {}))
                    continue
                th = rule.threshold
                group = {f: get_field(event, f) for f in th.group_by}
                key = (rule.id, tuple(sorted((k, str(v)) for k, v in group.items())))
                # Without a usable timestamp fall back to arrival order (1s apart).
                now = ts if ts is not None else float(index)
                win = windows[key]
                win.append(now)
                while win and now - win[0] > th.window_seconds:
                    win.popleft()
                if len(win) >= th.count and key not in fired:
                    fired.add(key)  # one alert per group until the window drains
                    alerts.append(self._alert(rule, event, len(win), group))
                elif len(win) < th.count:
                    fired.discard(key)
        alerts.sort(key=lambda a: -LEVELS.index(a.level))
        return alerts

    @staticmethod
    def _alert(rule: Rule, event: dict, count: int, group: dict) -> Alert:
        return Alert(
            rule_id=rule.id,
            title=rule.title,
            level=rule.level,
            techniques=rule.techniques,
            tactics=rule.tactics,
            timestamp=str(event.get("timestamp")) if event.get("timestamp") is not None else None,
            group=group,
            matched_events=count,
            sample=event,
        )
