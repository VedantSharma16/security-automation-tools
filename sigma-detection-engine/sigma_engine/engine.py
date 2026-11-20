"""Run compiled rules over an event stream and summarise the results."""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

from .rule import LEVELS, Rule

__all__ = ["Alert", "ScanResult", "read_events", "scan", "level_at_least"]

_TIME_FIELDS = ("UtcTime", "@timestamp", "timestamp", "TimeCreated", "time")
_HOST_FIELDS = ("Computer", "host.name", "hostname", "host")


def level_at_least(level: str, threshold: str) -> bool:
    return LEVELS.index(level) >= LEVELS.index(threshold)


def _first(event: Mapping[str, Any], names: Iterable[str]) -> str:
    for n in names:
        v = event.get(n)
        if v is None and "." in n:
            cur: Any = event
            for part in n.split("."):
                cur = cur.get(part) if isinstance(cur, Mapping) else None
            v = cur
        if v not in (None, "") and not isinstance(v, Mapping):
            return str(v)
    return ""


@dataclass
class Alert:
    rule_id: str
    rule_title: str
    level: str
    techniques: list[str]
    tactics: list[str]
    matched_identifiers: list[str]
    event_index: int
    timestamp: str
    host: str
    event: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    events_scanned: int
    rules_loaded: int
    alerts: list[Alert] = field(default_factory=list)

    @property
    def by_level(self) -> dict[str, int]:
        counts = Counter(a.level for a in self.alerts)
        return {lvl: counts[lvl] for lvl in reversed(LEVELS) if counts[lvl]}

    @property
    def by_rule(self) -> list[tuple[str, str, int]]:
        counts: Counter = Counter((a.rule_id, a.rule_title, a.level) for a in self.alerts)
        ordered = sorted(counts.items(), key=lambda kv: (-LEVELS.index(kv[0][2]), -kv[1]))
        return [(rid, title, n) for (rid, title, _), n in ordered]

    @property
    def techniques(self) -> list[str]:
        return sorted({t for a in self.alerts for t in a.techniques})

    def timeline(self) -> dict[str, list[Alert]]:
        """Alerts grouped per host and ordered by time - the analyst's view."""
        hosts: dict[str, list[Alert]] = defaultdict(list)
        for a in self.alerts:
            hosts[a.host or "unknown"].append(a)
        return {h: sorted(v, key=lambda a: (a.timestamp, a.event_index)) for h, v in sorted(hosts.items())}

    def max_level(self) -> str | None:
        return max((a.level for a in self.alerts), key=LEVELS.index, default=None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": {
                "events_scanned": self.events_scanned,
                "rules_loaded": self.rules_loaded,
                "alerts": len(self.alerts),
                "by_level": self.by_level,
                "techniques": self.techniques,
            },
            "alerts": [a.to_dict() for a in self.alerts],
        }


def read_events(path: str | Path) -> Iterator[dict[str, Any]]:
    """Yield events from a JSON-lines file or a JSON array file.

    Malformed lines are reported and skipped rather than aborting the scan -
    real log exports are rarely perfectly clean.
    """
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    stripped = text.lstrip()
    if stripped.startswith("["):
        data = json.loads(text)
        for item in data:
            if isinstance(item, dict):
                yield item
        return
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"warning: {path}:{lineno}: skipping malformed JSON ({exc.msg})", file=sys.stderr)
            continue
        if isinstance(obj, dict):
            yield obj


def scan(rules: list[Rule], events: Iterable[Mapping[str, Any]], min_level: str = "informational") -> ScanResult:
    """Evaluate every rule against every event."""
    active = [r for r in rules if r.level in LEVELS and level_at_least(r.level, min_level)]
    result = ScanResult(events_scanned=0, rules_loaded=len(active))
    for idx, event in enumerate(events):
        result.events_scanned += 1
        for rule in active:
            if not rule.applies_to(event):
                continue
            matched, hits = rule.evaluate(event)
            if matched:
                result.alerts.append(
                    Alert(
                        rule_id=rule.id,
                        rule_title=rule.title,
                        level=rule.level,
                        techniques=rule.techniques,
                        tactics=rule.tactics,
                        matched_identifiers=hits,
                        event_index=idx,
                        timestamp=_first(event, _TIME_FIELDS),
                        host=_first(event, _HOST_FIELDS),
                        event=dict(event),
                    )
                )
    return result
