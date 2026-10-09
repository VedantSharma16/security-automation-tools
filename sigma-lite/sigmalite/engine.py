"""Run rules over a stream of events, including sliding-window thresholds."""
from __future__ import annotations

import json
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

from .matchers import get_field
from .rules import Rule

TIME_FIELDS = ("@timestamp", "timestamp", "time", "TimeCreated", "UtcTime")


@dataclass
class Alert:
    rule_id: str
    title: str
    level: str
    techniques: list[str]
    tactics: list[str]
    event_count: int
    events: list[dict] = field(repr=False)
    group: str | None = None

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id, "title": self.title, "level": self.level,
            "techniques": self.techniques, "tactics": self.tactics,
            "event_count": self.event_count, "group": self.group, "events": self.events,
        }


def event_time(event: dict) -> float | None:
    for name in TIME_FIELDS:
        v = get_field(event, name)
        if v is None:
            continue
        if isinstance(v, (int, float)):
            return float(v)
        try:
            dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        except ValueError:
            continue
        return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()
    return None


def read_events(path: str | Path) -> Iterator[dict]:
    """Yield events from a ``.jsonl`` file or a JSON array file."""
    text = Path(path).read_text(encoding="utf-8").strip()
    if text.startswith("["):
        yield from json.loads(text)
        return
    for n, line in enumerate(text.splitlines(), 1):
        if line.strip():
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{n}: invalid JSON: {exc}") from exc


def _alert(rule: Rule, events: list[dict], group: str | None = None) -> Alert:
    return Alert(rule.id, rule.title, rule.level, rule.techniques, rule.tactics,
                 len(events), events, group)


def run(rules: Iterable[Rule], events: Iterable[dict]) -> list[Alert]:
    """Evaluate every rule against every event.

    Simple rules alert once per matching event. Aggregation rules keep a
    per-group sliding window and alert once when the threshold is crossed,
    then stay quiet for that group until its window drains (no alert storms).
    """
    rules = list(rules)
    windows: dict[tuple[str, str | None], deque] = defaultdict(deque)
    fired: set[tuple[str, str | None]] = set()
    alerts: list[Alert] = []
    for idx, event in enumerate(events):
        ts = event_time(event)
        for rule in rules:
            if not rule.matches(event):
                continue
            agg = rule.aggregation
            if agg is None:
                alerts.append(_alert(rule, [event]))
                continue
            group = None if agg.group_by is None else str(get_field(event, agg.group_by))
            key = (rule.id, group)
            win = windows[key]
            win.append((ts if ts is not None else float(idx), event))
            horizon = win[-1][0] - agg.timeframe
            while win and win[0][0] < horizon:
                win.popleft()
            if len(win) < agg.threshold:
                fired.discard(key)
            elif key not in fired:
                fired.add(key)
                alerts.append(_alert(rule, [e for _, e in win], group))
    return alerts
