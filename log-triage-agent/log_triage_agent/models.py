"""Shared data structures used across the parsing, detection, and reporting
stages of the pipeline."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class EventType(str, Enum):
    FAILED_PASSWORD = "failed_password"
    ACCEPTED_PASSWORD = "accepted_password"
    INVALID_USER = "invalid_user"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class LogEvent:
    timestamp: datetime
    host: str
    process: str
    pid: int
    event_type: EventType
    username: str
    source_ip: str
    port: int
    raw_line: str


@dataclass
class Finding:
    """A single detection surfaced by a detector, before enrichment."""

    finding_type: str
    severity: Severity
    source_ip: str
    summary: str
    events: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
