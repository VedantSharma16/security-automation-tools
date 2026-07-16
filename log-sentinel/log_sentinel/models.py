"""Data models shared across log-sentinel."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class LogEvent:
    """A single normalized SSH authentication event."""

    timestamp: datetime
    host: str
    source_ip: str
    user: str
    action: str  # "failed_password" | "accepted_login"
    raw_line: str
    facility: str = "sshd"


@dataclass
class Alert:
    """A detection produced by a rule against a set of LogEvents."""

    rule_id: str
    title: str
    severity: Severity
    description: str
    events: list[LogEvent] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    @property
    def source_ips(self) -> list[str]:
        seen: list[str] = []
        for event in self.events:
            if event.source_ip not in seen:
                seen.append(event.source_ip)
        return seen

    @property
    def users(self) -> list[str]:
        seen: list[str] = []
        for event in self.events:
            if event.user not in seen:
                seen.append(event.user)
        return seen
