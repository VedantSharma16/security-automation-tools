"""Parsing for OpenSSH-style auth logs (e.g. /var/log/auth.log).

Only a focused subset of sshd log lines is supported: failed/accepted
password attempts, including the "invalid user" variant. Lines that don't
match a known pattern are skipped rather than raising, since real-world auth
logs contain many unrelated entries (session opened/closed, pubkey auth,
etc.) that are out of scope for this tool.
"""

import re
from datetime import datetime
from typing import Iterable, Iterator, Optional

from .models import EventType, LogEvent

_LINE_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>\w+)\[(?P<pid>\d+)\]:\s+(?P<message>.+)$"
)

_FAILED_INVALID_RE = re.compile(
    r"^Failed password for invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_FAILED_VALID_RE = re.compile(
    r"^Failed password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_ACCEPTED_RE = re.compile(
    r"^Accepted password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)


def parse_line(line: str, year: Optional[int] = None) -> Optional[LogEvent]:
    """Parse a single auth.log line into a LogEvent, or None if unrecognized.

    `year` defaults to the current year since syslog timestamps omit it.
    Pass it explicitly for reproducible parsing of archived/sample logs.
    """
    line = line.rstrip("\n")
    if not line.strip():
        return None

    match = _LINE_RE.match(line)
    if not match:
        return None

    message = match.group("message")

    if invalid_match := _FAILED_INVALID_RE.match(message):
        event_type = EventType.INVALID_USER
        fields = invalid_match
    elif failed_match := _FAILED_VALID_RE.match(message):
        event_type = EventType.FAILED_PASSWORD
        fields = failed_match
    elif accepted_match := _ACCEPTED_RE.match(message):
        event_type = EventType.ACCEPTED_PASSWORD
        fields = accepted_match
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
        process=match.group("process"),
        pid=int(match.group("pid")),
        event_type=event_type,
        username=fields.group("user"),
        source_ip=fields.group("ip"),
        port=int(fields.group("port")),
        raw_line=line,
    )


def parse_lines(lines: Iterable[str], year: Optional[int] = None) -> Iterator[LogEvent]:
    for line in lines:
        event = parse_line(line, year=year)
        if event is not None:
            yield event


def parse_file(path: str, year: Optional[int] = None) -> list:
    with open(path, "r", encoding="utf-8") as f:
        return list(parse_lines(f, year=year))
