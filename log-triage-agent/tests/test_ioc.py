from datetime import datetime

from log_triage_agent.ioc import extract_iocs
from log_triage_agent.models import Event, EventType

TS = datetime(2024, 3, 4, 2, 0, 0)


def event(event_type, source_ip=None, username=None):
    return Event(
        timestamp=TS, host="web01", process="sshd", event_type=event_type, raw="synthetic",
        username=username, source_ip=source_ip,
    )


def test_extract_iocs_dedupes_and_sorts_ips():
    events = [
        event(EventType.AUTH_FAILURE, source_ip="203.0.113.7", username="root"),
        event(EventType.AUTH_FAILURE, source_ip="203.0.113.7", username="root"),
        event(EventType.INVALID_USER, source_ip="198.51.100.44", username="oracle"),
    ]
    iocs = extract_iocs(events)

    assert iocs.source_ips == ["198.51.100.44", "203.0.113.7"]
    assert "oracle" in iocs.usernames


def test_extract_iocs_filters_noisy_default_usernames():
    events = [
        event(EventType.AUTH_FAILURE, source_ip="203.0.113.7", username="root"),
        event(EventType.INVALID_USER, source_ip="203.0.113.7", username="admin"),
        event(EventType.INVALID_USER, source_ip="203.0.113.7", username="oracle"),
    ]
    iocs = extract_iocs(events)

    assert iocs.usernames == ["oracle"]


def test_successful_logins_do_not_produce_username_iocs():
    events = [event(EventType.AUTH_SUCCESS, source_ip="10.0.0.15", username="alice")]
    iocs = extract_iocs(events)

    assert iocs.usernames == []
    assert iocs.source_ips == ["10.0.0.15"]
