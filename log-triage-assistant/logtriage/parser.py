"""Parsing of Linux auth-log style syslog lines into structured Event objects.

Supports two common timestamp formats:
  - BSD syslog:  "Jan 10 03:22:15 host sshd[1234]: message"
  - RFC3339-ish: "2026-01-10T03:22:15 host sshd[1234]: message"

Recognized message kinds (set on Event.kind / Event.fields):
  - ssh_failed_password
  - ssh_accepted
  - sudo_command
  - useradd
  - crontab_replace
  - other (unrecognized message, kept for completeness)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

_LINE_RE = re.compile(
    r"^(?P<ts>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[\w./-]+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

_BSD_TS_RE = re.compile(r"^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}$")

_FAILED_PW_RE = re.compile(
    r"Failed password for (?:(?P<invalid>invalid user) )?(?P<user>\S+) "
    r"from (?P<ip>[\d.]+) port (?P<port>\d+)"
)
_ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
)
_SUDO_RE = re.compile(
    r"(?P<invoker>\S+)\s*:\s*TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>\S+)\s*;\s*"
    r"USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.*)"
)
_USERADD_RE = re.compile(r"new user:\s*name=(?P<name>[^,]+),\s*UID=(?P<uid>\d+)")
_CRONTAB_RE = re.compile(r"\((?P<user>\S+)\)\s*(?P<action>REPLACE|BEGIN EDIT|END EDIT)")


@dataclass
class Event:
    """A single parsed log line."""

    timestamp: datetime
    host: str
    process: str
    pid: Optional[int]
    message: str
    raw: str
    kind: str = "other"
    fields: dict = field(default_factory=dict)


def _resolve_year(ts_str: str, default_year: int) -> datetime:
    if _BSD_TS_RE.match(ts_str):
        dt = datetime.strptime(f"{default_year} {ts_str}", "%Y %b %d %H:%M:%S")
        return dt
    return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S")


def _classify(message: str) -> tuple[str, dict]:
    m = _FAILED_PW_RE.search(message)
    if m:
        return "ssh_failed_password", {
            "user": m.group("user"),
            "invalid_user": m.group("invalid") is not None,
            "ip": m.group("ip"),
            "port": int(m.group("port")),
        }

    m = _ACCEPTED_RE.search(message)
    if m:
        return "ssh_accepted", {
            "user": m.group("user"),
            "method": m.group("method"),
            "ip": m.group("ip"),
            "port": int(m.group("port")),
        }

    m = _SUDO_RE.search(message)
    if m:
        return "sudo_command", {
            "invoker": m.group("invoker"),
            "target_user": m.group("target_user"),
            "command": m.group("command").strip(),
        }

    m = _USERADD_RE.search(message)
    if m:
        return "useradd", {
            "name": m.group("name").strip(),
            "uid": int(m.group("uid")),
        }

    m = _CRONTAB_RE.search(message)
    if m:
        return "crontab_replace", {
            "user": m.group("user"),
            "action": m.group("action"),
        }

    return "other", {}


def parse_line(line: str, default_year: Optional[int] = None) -> Optional[Event]:
    """Parse a single log line into an Event, or None if it doesn't match the syslog shape."""
    line = line.rstrip("\n")
    if not line.strip():
        return None

    m = _LINE_RE.match(line)
    if not m:
        return None

    year = default_year or datetime.now().year
    try:
        timestamp = _resolve_year(m.group("ts"), year)
    except ValueError:
        return None

    # BSD syslog has no year; if the resulting date is in the future relative to
    # "now", it almost certainly belongs to last year (log rolled over New Year's).
    if default_year is None and timestamp > datetime.now():
        timestamp = timestamp.replace(year=year - 1)

    pid = int(m.group("pid")) if m.group("pid") else None
    message = m.group("message")
    kind, fields_ = _classify(message)

    return Event(
        timestamp=timestamp,
        host=m.group("host"),
        process=m.group("process"),
        pid=pid,
        message=message,
        raw=line,
        kind=kind,
        fields=fields_,
    )


def parse_file(path: str | Path, default_year: Optional[int] = None) -> list[Event]:
    """Parse every recognizable line in a log file into a list of Events, in order."""
    events: list[Event] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            event = parse_line(line, default_year=default_year)
            if event is not None:
                events.append(event)
    return events
