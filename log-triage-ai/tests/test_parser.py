from datetime import datetime

from logtriage.models import EventType
from logtriage.parser import parse_line, parse_log

YEAR = 2026


def test_parses_failed_login():
    line = "Jan 10 03:14:01 web01 sshd[2001]: Failed password for invalid user admin from 203.0.113.5 port 51501 ssh2"
    event = parse_line(line, YEAR)

    assert event is not None
    assert event.event_type == EventType.AUTH_FAILURE
    assert event.user == "admin"
    assert event.source_ip == "203.0.113.5"
    assert event.port == 51501
    assert event.timestamp == datetime(2026, 1, 10, 3, 14, 1)


def test_parses_accepted_login():
    line = "Jan 10 03:14:40 web01 sshd[2007]: Accepted password for root from 203.0.113.5 port 51507 ssh2"
    event = parse_line(line, YEAR)

    assert event.event_type == EventType.AUTH_SUCCESS
    assert event.user == "root"
    assert event.source_ip == "203.0.113.5"


def test_parses_sudo_command():
    line = "Jan 10 03:15:02 web01 sudo:   root : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/bin/chmod 4755 /bin/bash"
    event = parse_line(line, YEAR)

    assert event.event_type == EventType.SUDO_COMMAND
    assert event.user == "root"
    assert event.command == "/bin/chmod 4755 /bin/bash"


def test_unrecognized_syslog_line_is_unknown_not_none():
    line = "Jan 10 03:12:44 web01 CRON[1042]: pam_unix(cron:session): session opened for user root"
    event = parse_line(line, YEAR)

    assert event is not None
    assert event.event_type == EventType.UNKNOWN


def test_garbage_line_returns_none():
    assert parse_line("not a syslog line at all", YEAR) is None


def test_parse_log_skips_blank_lines():
    lines = [
        "Jan 10 03:14:01 web01 sshd[2001]: Failed password for invalid user admin from 203.0.113.5 port 51501 ssh2\n",
        "\n",
        "   \n",
        "Jan 10 03:14:40 web01 sshd[2007]: Accepted password for root from 203.0.113.5 port 51507 ssh2\n",
    ]
    events = parse_log(lines, YEAR)
    assert len(events) == 2
