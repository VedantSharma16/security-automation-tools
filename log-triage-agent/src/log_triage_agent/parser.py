"""Parses OpenSSH/sudo syslog-style lines into normalized Event objects.

Supports the standard syslog line shape:
    <Mon> <day> <HH:MM:SS> <host> <process>[<pid>]: <message>

Recognized message patterns:
    - "Failed password for invalid user <user> from <ip> port <port> ssh2"
    - "Failed password for <user> from <ip> port <port> ssh2"
    - "Accepted password for <user> from <ip> port <port> ssh2"
    - "Accepted publickey for <user> from <ip> port <port> ssh2"
    - "Invalid user <user> from <ip> port <port>"
    - sudo: "<user> : TTY=<tty> ; PWD=<path> ; USER=<target> ; COMMAND=<cmd>"

Lines that don't match a known pattern are skipped (not raised as errors), since
real-world logs are noisy and a triage tool should degrade gracefully.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from datetime import datetime

from log_triage_agent.models import Event, EventType

_SYSLOG_LINE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[\w.\-/]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

_FAILED_INVALID_USER = re.compile(
    r"Failed password for invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port (?P<port>\d+)"
)
_FAILED_VALID_USER = re.compile(
    r"Failed password for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port (?P<port>\d+)"
)
_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port (?P<port>\d+)"
)
_INVALID_USER_NOTICE = re.compile(
    r"^Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"
)
_SUDO_COMMAND = re.compile(
    r"(?P<user>\S+)\s*:.*?\bUSER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.+)$"
)


def _parse_timestamp(ts: str, assume_year: int) -> datetime:
    return datetime.strptime(f"{assume_year} {ts}", "%Y %b %d %H:%M:%S")


def parse_line(line: str, assume_year: int) -> Event | None:
    """Parse a single syslog line into an Event, or None if it isn't recognized."""
    match = _SYSLOG_LINE.match(line.strip())
    if not match:
        return None

    timestamp = _parse_timestamp(match["ts"], assume_year)
    host = match["host"]
    process = match["process"]
    message = match["message"]

    if m := _FAILED_INVALID_USER.search(message):
        return Event(
            timestamp=timestamp,
            host=host,
            process=process,
            event_type=EventType.INVALID_USER,
            raw=line.rstrip("\n"),
            username=m["user"],
            source_ip=m["ip"],
        )
    if m := _FAILED_VALID_USER.search(message):
        return Event(
            timestamp=timestamp,
            host=host,
            process=process,
            event_type=EventType.AUTH_FAILURE,
            raw=line.rstrip("\n"),
            username=m["user"],
            source_ip=m["ip"],
        )
    if m := _ACCEPTED.search(message):
        return Event(
            timestamp=timestamp,
            host=host,
            process=process,
            event_type=EventType.AUTH_SUCCESS,
            raw=line.rstrip("\n"),
            username=m["user"],
            source_ip=m["ip"],
        )
    if m := _INVALID_USER_NOTICE.search(message):
        return Event(
            timestamp=timestamp,
            host=host,
            process=process,
            event_type=EventType.INVALID_USER,
            raw=line.rstrip("\n"),
            username=m["user"],
            source_ip=m["ip"],
        )
    if "sudo" in process and (m := _SUDO_COMMAND.search(message)):
        return Event(
            timestamp=timestamp,
            host=host,
            process=process,
            event_type=EventType.SUDO_COMMAND,
            raw=line.rstrip("\n"),
            username=m["user"],
            extra={"target_user": m["target_user"], "command": m["command"].strip()},
        )

    return None


def parse_lines(lines: Iterable[str], assume_year: int | None = None) -> Iterator[Event]:
    """Parse an iterable of raw log lines into Events, silently dropping unrecognized ones."""
    year = assume_year or datetime.now().year
    for line in lines:
        if not line.strip():
            continue
        event = parse_line(line, year)
        if event is not None:
            yield event


def parse_file(path: str, assume_year: int | None = None) -> list[Event]:
    with open(path, encoding="utf-8") as fh:
        return list(parse_lines(fh, assume_year=assume_year))
