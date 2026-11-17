"""Run a compiled rule set over a stream of events and emit alerts."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

import yaml

from .matcher import get_field, _MISSING
from .rule import LEVEL_RANK, Rule

# Fields copied from the matching event into the alert for analyst context.
CONTEXT_FIELDS = ("Computer", "User", "Image", "CommandLine", "ParentImage",
                  "TargetObject", "TargetImage", "DestinationIp", "DestinationPort")
HOST_FIELDS = ("Computer", "host.name", "hostname", "host")
TIME_FIELDS = ("UtcTime", "@timestamp", "timestamp", "TimeCreated")


@dataclass
class Alert:
    rule_id: str
    rule_title: str
    level: str
    tags: list[str]
    techniques: list[str]
    tactics: list[str]
    host: str | None
    timestamp: str | None
    event_index: int
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _first(event: Mapping[str, Any], names: Iterable[str], field_map) -> Any:
    for n in names:
        v = get_field(event, n, field_map)
        if v is not _MISSING and v not in (None, ""):
            return v
    return None


def load_field_map(path: str | Path | None) -> dict[str, str]:
    """Load a YAML mapping of Sigma field name -> log field path."""
    if not path:
        return {}
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    mapping = data.get("fields", data)
    if not isinstance(mapping, Mapping):
        raise ValueError(f"{path}: field map must be a mapping")
    return {str(k): str(v) for k, v in mapping.items()}


def read_events(path: str | Path) -> Iterator[dict[str, Any]]:
    """Read events from a JSON array file or JSON Lines file."""
    text = Path(path).read_text(encoding="utf-8")
    stripped = text.lstrip()
    if stripped.startswith("["):
        yield from json.loads(stripped)
        return
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{lineno}: invalid JSON: {exc.msg}") from exc


class Engine:
    def __init__(self, rules: Iterable[Rule], field_map: Mapping[str, str] | None = None,
                 min_level: str = "informational"):
        self.field_map = dict(field_map or {})
        self.min_rank = LEVEL_RANK[min_level]
        self.rules = [r for r in rules if LEVEL_RANK[r.level] >= self.min_rank]

    def match_event(self, event: Mapping[str, Any], index: int = 0) -> list[Alert]:
        logsource = event.get("logsource") if isinstance(event.get("logsource"), Mapping) else None
        alerts = []
        for rule in self.rules:
            if not rule.applies_to(logsource) or not rule.matches(event):
                continue
            ctx = {f: v for f in CONTEXT_FIELDS
                   if (v := get_field(event, f, self.field_map)) is not _MISSING and v is not None}
            alerts.append(Alert(
                rule_id=rule.id, rule_title=rule.title, level=rule.level, tags=rule.tags,
                techniques=rule.techniques, tactics=rule.tactics,
                host=_first(event, HOST_FIELDS, self.field_map),
                timestamp=_first(event, TIME_FIELDS, self.field_map),
                event_index=index, context=ctx,
            ))
        return alerts

    def scan(self, events: Iterable[Mapping[str, Any]]) -> list[Alert]:
        alerts: list[Alert] = []
        for i, ev in enumerate(events):
            alerts.extend(self.match_event(ev, i))
        return alerts
