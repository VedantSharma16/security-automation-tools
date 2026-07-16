"""Parser for OpenSSH auth.log-style syslog lines."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from .models import LogEvent

_LINE_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<message>.+)$"
)
_FAILED_RE = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port \d+"
)
_ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[\d.]+) port \d+"
)


def parse_line(line: str, year: int | None = None) -> LogEvent | None:
    """Parse a single syslog line into a LogEvent, or None if it isn't a
    recognized authentication event (e.g. "session opened" lines are ignored).
    """
    line = line.rstrip("\n")
    match = _LINE_RE.match(line)
    if not match:
        return None

    message = match.group("message")
    failed = _FAILED_RE.search(message)
    accepted = _ACCEPTED_RE.search(message)
    if failed:
        action, user, ip = "failed_password", failed.group("user"), failed.group("ip")
    elif accepted:
        action, user, ip = "accepted_login", accepted.group("user"), accepted.group("ip")
    else:
        return None

    resolved_year = year or datetime.now().year
    timestamp = datetime.strptime(
        f"{resolved_year} {match.group('month')} {match.group('day')} {match.group('time')}",
        "%Y %b %d %H:%M:%S",
    )
    return LogEvent(
        timestamp=timestamp,
        host=match.group("host"),
        source_ip=ip,
        user=user,
        action=action,
        raw_line=line,
    )


def parse_file(path: str | Path, year: int | None = None) -> list[LogEvent]:
    """Parse every recognized authentication event out of a log file."""
    events: list[LogEvent] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            event = parse_line(line, year=year)
            if event is not None:
                events.append(event)
    return events
