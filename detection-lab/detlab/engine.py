"""Run compiled rules over a stream of events and collect alerts."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .rules import LEVELS, Rule

LOGSOURCE_KEY = "_logsource"


@dataclass
class Alert:
    rule_id: str
    rule_title: str
    level: str
    techniques: list[str]
    tactics: list[str]
    event_index: int
    matched_selections: list[str]
    event: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "level": self.level,
            "techniques": self.techniques,
            "tactics": self.tactics,
            "event_index": self.event_index,
            "matched_selections": self.matched_selections,
            "event": self.event,
        }


@dataclass
class ScanResult:
    alerts: list[Alert]
    events_scanned: int
    rules_loaded: int
    event_errors: list[str] = field(default_factory=list)

    def by_level(self) -> dict[str, int]:
        counts = Counter(a.level for a in self.alerts)
        return {lvl: counts[lvl] for lvl in reversed(LEVELS) if counts[lvl]}

    def by_rule(self) -> list[tuple[str, str, int]]:
        counts = Counter((a.rule_title, a.level) for a in self.alerts)
        ordered = sorted(counts.items(), key=lambda kv: (-LEVELS.index(kv[0][1]), -kv[1], kv[0][0]))
        return [(title, level, n) for (title, level), n in ordered]

    def to_dict(self) -> dict[str, Any]:
        return {
            "events_scanned": self.events_scanned,
            "rules_loaded": self.rules_loaded,
            "alert_count": len(self.alerts),
            "by_level": self.by_level(),
            "event_errors": self.event_errors,
            "alerts": [a.to_dict() for a in self.alerts],
        }


def logsource_applies(rule: Rule, event: dict[str, Any]) -> bool:
    """If an event declares its log source, only rules for that source apply.

    Events without a ``_logsource`` key are evaluated by every rule, which is
    the convenient default for ad-hoc JSONL exports.
    """
    declared = event.get(LOGSOURCE_KEY)
    if not isinstance(declared, dict):
        return True
    for key in ("product", "category", "service"):
        if key in rule.logsource and key in declared and str(rule.logsource[key]).lower() != str(declared[key]).lower():
            return False
    return True


def scan(rules: list[Rule], events: Iterable[dict[str, Any]], min_level: str = "informational") -> ScanResult:
    threshold = LEVELS.index(min_level)
    active = [r for r in rules if r.level_rank >= threshold and r.status != "deprecated"]
    alerts: list[Alert] = []
    count = 0
    for idx, event in enumerate(events):
        count += 1
        for rule in active:
            if logsource_applies(rule, event) and rule.matches(event):
                alerts.append(
                    Alert(
                        rule_id=rule.id,
                        rule_title=rule.title,
                        level=rule.level,
                        techniques=rule.techniques,
                        tactics=rule.tactics,
                        event_index=idx,
                        matched_selections=rule.matched_selections(event),
                        event=event,
                    )
                )
    return ScanResult(alerts=alerts, events_scanned=count, rules_loaded=len(active))


def load_events(path: Path | str) -> tuple[list[dict[str, Any]], list[str]]:
    """Load events from a JSON array file or JSON Lines; returns (events, errors)."""
    text = Path(path).read_text(encoding="utf-8")
    stripped = text.lstrip()
    if stripped.startswith("["):
        data = json.loads(stripped)
        events = [e for e in data if isinstance(e, dict)]
        errors = [f"item {i}: not a JSON object" for i, e in enumerate(data) if not isinstance(e, dict)]
        return events, errors
    events, errors = [], []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"line {lineno}: {exc.msg}")
            continue
        if isinstance(obj, dict):
            events.append(obj)
        else:
            errors.append(f"line {lineno}: not a JSON object")
    return events, errors
