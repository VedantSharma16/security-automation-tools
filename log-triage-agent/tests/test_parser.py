from log_triage_agent.models import EventType
from log_triage_agent.parser import parse_file, parse_line


def test_parses_failed_password_invalid_user():
    line = "Mar  4 02:11:03 web01 sshd[1001]: Failed password for invalid user oracle from 203.0.113.7 port 51422 ssh2"
    event = parse_line(line, assume_year=2024)

    assert event is not None
    assert event.event_type == EventType.INVALID_USER
    assert event.username == "oracle"
    assert event.source_ip == "203.0.113.7"
    assert event.host == "web01"
    assert event.timestamp.month == 3 and event.timestamp.day == 4


def test_parses_failed_password_valid_user():
    line = "Mar  4 02:11:14 web01 sshd[1004]: Failed password for root from 203.0.113.7 port 51448 ssh2"
    event = parse_line(line, assume_year=2024)

    assert event.event_type == EventType.AUTH_FAILURE
    assert event.username == "root"
    assert event.source_ip == "203.0.113.7"


def test_parses_accepted_password():
    line = "Mar  4 02:12:02 web01 sshd[1008]: Accepted password for deploy from 203.0.113.7 port 51488 ssh2"
    event = parse_line(line, assume_year=2024)

    assert event.event_type == EventType.AUTH_SUCCESS
    assert event.username == "deploy"


def test_parses_sudo_command():
    line = "Mar  4 02:12:05 web01 sudo:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash"
    event = parse_line(line, assume_year=2024)

    assert event.event_type == EventType.SUDO_COMMAND
    assert event.username == "deploy"
    assert event.extra["target_user"] == "root"
    assert event.extra["command"] == "/bin/bash"


def test_unrecognized_line_returns_none():
    line = "Mar  4 02:12:05 web01 kernel: some totally unrelated kernel message"
    assert parse_line(line, assume_year=2024) is None


def test_blank_and_malformed_lines_are_skipped_in_bulk_parse(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        "\n"
        "not a syslog line at all\n"
        "Mar  4 02:11:03 web01 sshd[1001]: Failed password for invalid user oracle from 203.0.113.7 port 51422 ssh2\n"
    )
    events = parse_file(str(log), assume_year=2024)
    assert len(events) == 1
    assert events[0].username == "oracle"
