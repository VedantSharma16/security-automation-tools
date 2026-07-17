"""Core data structures shared across the parser, detectors, and reporting layers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class EventType(str, Enum):
    AUTH_FAILURE = "auth_failure"
    AUTH_SUCCESS = "auth_success"
    INVALID_USER = "invalid_user"
    SUDO_COMMAND = "sudo_command"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]


@dataclass
class Event:
    """A single normalized log line."""

    timestamp: datetime
    host: str
    process: str
    event_type: EventType
    raw: str
    username: str | None = None
    source_ip: str | None = None
    extra: dict = field(default_factory=dict)


@dataclass
class Finding:
    """A detector's conclusion about a group of related events."""

    title: str
    severity: Severity
    technique_id: str
    technique_name: str
    description: str
    source_ip: str | None = None
    username: str | None = None
    event_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "mitre_attack": {"id": self.technique_id, "name": self.technique_name},
            "description": self.description,
            "source_ip": self.source_ip,
            "username": self.username,
            "event_count": self.event_count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


@dataclass
class IOCs:
    """Indicators of compromise pulled out of the parsed events."""

    source_ips: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"source_ips": self.source_ips, "usernames": self.usernames}


@dataclass
class Report:
    """Final output of the triage agent: findings, IOCs, and a narrative summary."""

    findings: list[Finding]
    iocs: IOCs
    events_analyzed: int
    narrative: str
    narrative_source: str  # "llm" or "deterministic"

    def highest_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)
