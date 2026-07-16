from datetime import datetime

from log_sentinel.parser import parse_file, parse_line


def test_parse_failed_password_line():
    line = (
        "Jul 14 03:12:01 web01 sshd[1001]: Failed password for invalid user admin "
        "from 203.0.113.7 port 51501 ssh2"
    )
    event = parse_line(line, year=2026)
    assert event is not None
    assert event.action == "failed_password"
    assert event.user == "admin"
    assert event.source_ip == "203.0.113.7"
    assert event.host == "web01"
    assert event.timestamp == datetime(2026, 7, 14, 3, 12, 1)


def test_parse_accepted_publickey_line():
    line = "Jul 14 09:45:10 web01 sshd[1100]: Accepted publickey for deploy from 10.0.0.5 port 55210 ssh2"
    event = parse_line(line, year=2026)
    assert event is not None
    assert event.action == "accepted_login"
    assert event.user == "deploy"
    assert event.source_ip == "10.0.0.5"


def test_parse_ignores_unrelated_lines():
    assert parse_line("Jul 14 09:45:11 web01 sshd[1100]: session opened for user deploy by (uid=1001)") is None
    assert parse_line("not a syslog line at all") is None


def test_parse_file_reads_only_recognized_events(tmp_path):
    log_path = tmp_path / "auth.log"
    log_path.write_text(
        "Jul 14 03:12:01 web01 sshd[1001]: Failed password for invalid user admin "
        "from 203.0.113.7 port 51501 ssh2\n"
        "Jul 14 03:12:02 web01 sshd[1001]: session opened for user admin\n"
    )
    events = parse_file(log_path, year=2026)
    assert len(events) == 1
    assert events[0].user == "admin"


def test_parse_file_matches_sample_log_event_count():
    from pathlib import Path

    sample = Path(__file__).resolve().parent.parent / "data" / "sample_auth.log"
    events = parse_file(sample, year=2026)
    assert len(events) == 11
