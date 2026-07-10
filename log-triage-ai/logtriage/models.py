from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class EventType(str, Enum):
    AUTH_FAILURE = "auth_failure"
    AUTH_SUCCESS = "auth_success"
    SUDO_COMMAND = "sudo_command"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class LogEvent:
    timestamp: datetime
    host: str
    process: str
    raw: str
    event_type: EventType
    user: str | None = None
    source_ip: str | None = None
    port: int | None = None
    command: str | None = None


@dataclass
class Alert:
    id: str
    type: str
    severity: str  # "low" | "medium" | "high" | "critical"
    title: str
    description: str
    mitre_technique: str
    source_ip: str | None
    related_raw: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
