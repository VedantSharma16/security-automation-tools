"""Parser for OpenSSH auth log lines (syslog format)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Iterable, Iterator, Optional


class EventType(str, Enum):
    ACCEPTED = "ACCEPTED"
    FAILED_PASSWORD = "FAILED_PASSWORD"
    FAILED_INVALID_USER = "FAILED_INVALID_USER"
    INVALID_USER = "INVALID_USER"


@dataclass(frozen=True)
class LogEntry:
    timestamp: datetime
    event: EventType
    user: str
    source_ip: str
    port: Optional[int]
    raw: str


_TIMESTAMP_RE = r"(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"

_PATTERNS = [
    (
        EventType.FAILED_INVALID_USER,
        re.compile(
            _TIMESTAMP_RE
            + r".*sshd.*?: Failed password for invalid user (?P<user>\S+) "
            r"from (?P<ip>[\d.:a-fA-F]+) port (?P<port>\d+)"
        ),
    ),
    (
        EventType.FAILED_PASSWORD,
        re.compile(
            _TIMESTAMP_RE
            + r".*sshd.*?: Failed password for (?P<user>\S+) "
            r"from (?P<ip>[\d.:a-fA-F]+) port (?P<port>\d+)"
        ),
    ),
    (
        EventType.INVALID_USER,
        re.compile(
            _TIMESTAMP_RE
            + r".*sshd.*?: Invalid user (?P<user>\S+) "
            r"from (?P<ip>[\d.:a-fA-F]+)(?: port (?P<port>\d+))?"
        ),
    ),
    (
        EventType.ACCEPTED,
        re.compile(
            _TIMESTAMP_RE
            + r".*sshd.*?: Accepted (?:password|publickey|keyboard-interactive/pam) "
            r"for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port (?P<port>\d+)"
        ),
    ),
]


def _parse_timestamp(ts: str, year: int) -> datetime:
    # Syslog timestamps omit the year; the caller supplies one (defaults to
    # the current year at parse time, since logs are almost always current-year).
    normalized = re.sub(r"\s+", " ", ts.strip())
    return datetime.strptime(f"{year} {normalized}", "%Y %b %d %H:%M:%S")


def parse_line(line: str, year: Optional[int] = None) -> Optional[LogEntry]:
    """Parse a single auth.log line into a LogEntry, or None if it doesn't match."""
    if year is None:
        year = datetime.now().year

    for event_type, pattern in _PATTERNS:
        match = pattern.search(line)
        if not match:
            continue
        groups = match.groupdict()
        port = int(groups["port"]) if groups.get("port") else None
        return LogEntry(
            timestamp=_parse_timestamp(groups["ts"], year),
            event=event_type,
            user=groups["user"],
            source_ip=groups["ip"],
            port=port,
            raw=line.rstrip("\n"),
        )
    return None


def parse_lines(lines: Iterable[str], year: Optional[int] = None) -> Iterator[LogEntry]:
    for line in lines:
        entry = parse_line(line, year=year)
        if entry is not None:
            yield entry


def parse_file(path: str | Path, year: Optional[int] = None) -> list[LogEntry]:
    path = Path(path)
    with path.open("r", encoding="utf-8", errors="replace") as f:
        return list(parse_lines(f, year=year))
