"""Correlate individual alerts into per-host incidents.

Single-rule alerts are noisy; what an IR analyst actually wants is "this
host shows execution -> credential access -> impact within 20 minutes".
Alerts are grouped by host and split into incidents wherever the gap
between consecutive alerts exceeds ``window`` minutes. An incident that
spans several ATT&CK tactics is escalated one severity level, since
multi-stage activity is far less likely to be a benign false positive.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

from .attack import TACTIC_ORDER, TACTICS
from .engine import Alert
from .rule import LEVEL_RANK, LEVELS

_TS_FORMATS = ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S")
MULTI_STAGE_TACTICS = 3


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        dt = None
        for fmt in _TS_FORMATS:
            try:
                dt = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@dataclass
class Incident:
    host: str
    alerts: list[Alert] = field(default_factory=list)
    start: datetime | None = None
    end: datetime | None = None

    @property
    def tactics(self) -> list[str]:
        seen = {t for a in self.alerts for t in a.tactics}
        return sorted(seen, key=lambda t: TACTIC_ORDER.get(t, 99))

    @property
    def techniques(self) -> list[str]:
        return sorted({t for a in self.alerts for t in a.techniques})

    @property
    def base_level(self) -> str:
        return max((a.level for a in self.alerts), key=LEVEL_RANK.__getitem__)

    @property
    def multi_stage(self) -> bool:
        return len(self.tactics) >= MULTI_STAGE_TACTICS

    @property
    def level(self) -> str:
        rank = LEVEL_RANK[self.base_level] + (1 if self.multi_stage else 0)
        return LEVELS[min(rank, len(LEVELS) - 1)]

    @property
    def kill_chain(self) -> str:
        return " → ".join(TACTICS.get(t, t) for t in self.tactics) or "—"

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "level": self.level,
            "multi_stage": self.multi_stage,
            "start": self.start.isoformat() if self.start else None,
            "end": self.end.isoformat() if self.end else None,
            "tactics": self.tactics,
            "techniques": self.techniques,
            "alert_count": len(self.alerts),
            "rules": sorted({a.rule_title for a in self.alerts}),
        }


def correlate(alerts: Iterable[Alert], window_minutes: float = 30.0) -> list[Incident]:
    by_host: dict[str, list[tuple[datetime | None, Alert]]] = defaultdict(list)
    for a in alerts:
        by_host[a.host or "unknown"].append((parse_ts(a.timestamp), a))

    incidents: list[Incident] = []
    for host, items in by_host.items():
        timed = sorted((x for x in items if x[0] is not None), key=lambda x: x[0])
        untimed = [a for ts, a in items if ts is None]
        current: Incident | None = None
        for ts, alert in timed:
            if current is None or (ts - current.end).total_seconds() > window_minutes * 60:
                current = Incident(host=host, start=ts, end=ts)
                incidents.append(current)
            current.alerts.append(alert)
            current.end = ts
        if untimed:
            incidents.append(Incident(host=host, alerts=untimed))

    return sorted(
        incidents,
        key=lambda i: (-LEVEL_RANK[i.level], -len(i.tactics), i.start or datetime.max.replace(tzinfo=timezone.utc)),
    )
