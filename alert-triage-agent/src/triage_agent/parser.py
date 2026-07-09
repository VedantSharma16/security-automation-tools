"""Turns raw log text into normalized LogEvent objects."""

from __future__ import annotations

from pathlib import Path

from .models import LogEvent


def parse_lines(text: str, source: str = "<stream>") -> list[LogEvent]:
    """Split raw log text into LogEvent records, skipping blank lines."""
    events = []
    for i, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            continue
        events.append(LogEvent(line_number=i, raw=raw, source=source))
    return events


def parse_file(path: str | Path) -> list[LogEvent]:
    path = Path(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    return parse_lines(text, source=str(path))
