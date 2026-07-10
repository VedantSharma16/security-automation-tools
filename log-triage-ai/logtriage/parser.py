"""Parser for Linux-style syslog auth logs (sshd, sudo).

Supports the standard `/var/log/auth.log` format, which omits the year:

    Jan 10 03:14:15 web01 sshd[1234]: Failed password for invalid user admin \
from 203.0.113.5 port 51515 ssh2
"""

from __future__ import annotations

import re
from datetime import datetime

from .models import EventType, LogEvent

_SYSLOG_LINE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>[\w.\-]+)(\[\d+\])?:\s+(?P<message>.*)$"
)

_FAILED_LOGIN = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9.]+) port (?P<port>\d+)"
)

_ACCEPTED_LOGIN = re.compile(
    r"Accepted \S+ for (?P<user>\S+) from (?P<ip>[0-9.]+) port (?P<port>\d+)"
)

_SUDO_COMMAND = re.compile(
    r"^(?P<user>\S+)\s*:.*\bCOMMAND=(?P<command>.+)$"
)


def _parse_timestamp(month: str, day: str, time_str: str, year: int) -> datetime:
    return datetime.strptime(f"{year} {month} {int(day):02d} {time_str}", "%Y %b %d %H:%M:%S")


def parse_line(line: str, year: int) -> LogEvent | None:
    """Parse a single auth.log line into a LogEvent, or None if unrecognized."""
    match = _SYSLOG_LINE.match(line.rstrip("\n"))
    if not match:
        return None

    timestamp = _parse_timestamp(match["month"], match["day"], match["time"], year)
    host = match["host"]
    process = match["process"]
    message = match["message"]
    raw = line.rstrip("\n")

    if process == "sshd":
        failed = _FAILED_LOGIN.search(message)
        if failed:
            return LogEvent(
                timestamp=timestamp,
                host=host,
                process=process,
                raw=raw,
                event_type=EventType.AUTH_FAILURE,
                user=failed["user"],
                source_ip=failed["ip"],
                port=int(failed["port"]),
            )
        accepted = _ACCEPTED_LOGIN.search(message)
        if accepted:
            return LogEvent(
                timestamp=timestamp,
                host=host,
                process=process,
                raw=raw,
                event_type=EventType.AUTH_SUCCESS,
                user=accepted["user"],
                source_ip=accepted["ip"],
                port=int(accepted["port"]),
            )

    if process == "sudo":
        sudo_match = _SUDO_COMMAND.match(message)
        if sudo_match:
            return LogEvent(
                timestamp=timestamp,
                host=host,
                process=process,
                raw=raw,
                event_type=EventType.SUDO_COMMAND,
                user=sudo_match["user"],
                command=sudo_match["command"].strip(),
            )

    return LogEvent(
        timestamp=timestamp,
        host=host,
        process=process,
        raw=raw,
        event_type=EventType.UNKNOWN,
    )


def parse_log(lines: list[str], year: int) -> list[LogEvent]:
    """Parse every line of an auth.log file, skipping lines that don't match."""
    events = []
    for line in lines:
        if not line.strip():
            continue
        event = parse_line(line, year)
        if event is not None:
            events.append(event)
    return events
