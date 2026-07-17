"""Pulls a deduplicated indicator-of-compromise list out of parsed events."""

from __future__ import annotations

from log_triage_agent.models import Event, EventType, IOCs

# Usernames that are expected to fail auth constantly (default system accounts) and add
# noise rather than signal if surfaced as IOCs on their own.
_NOISY_USERNAMES = frozenset({"root", "admin", "test", "guest"})


def extract_iocs(events: list[Event]) -> IOCs:
    ips: set[str] = set()
    users: set[str] = set()

    for e in events:
        if e.source_ip:
            ips.add(e.source_ip)
        if e.username and e.event_type in (EventType.AUTH_FAILURE, EventType.INVALID_USER):
            users.add(e.username)

    return IOCs(
        source_ips=sorted(ips),
        usernames=sorted(u for u in users if u.lower() not in _NOISY_USERNAMES),
    )
