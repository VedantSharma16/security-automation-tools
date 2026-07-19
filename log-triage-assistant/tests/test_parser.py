from datetime import datetime
from pathlib import Path

from logtriage.parser import parse_file, parse_line

FIXTURES = Path(__file__).parent / "fixtures"


def test_parses_failed_password_line():
    event = parse_line(
        "Jan 10 03:22:10 webserver sshd[1201]: Failed password for invalid user admin "
        "from 203.0.113.5 port 51501 ssh2",
        default_year=2026,
    )
    assert event is not None
    assert event.kind == "ssh_failed_password"
    assert event.fields["user"] == "admin"
    assert event.fields["invalid_user"] is True
    assert event.fields["ip"] == "203.0.113.5"
    assert event.timestamp == datetime(2026, 1, 10, 3, 22, 10)
    assert event.process == "sshd"
    assert event.pid == 1201


def test_parses_accepted_login_line():
    event = parse_line(
        "Jan 10 03:23:15 webserver sshd[1207]: Accepted password for root "
        "from 203.0.113.5 port 51530 ssh2",
        default_year=2026,
    )
    assert event.kind == "ssh_accepted"
    assert event.fields["user"] == "root"
    assert event.fields["method"] == "password"


def test_parses_sudo_line():
    event = parse_line(
        "Jan 10 03:25:40 webserver sudo: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; "
        "USER=root ; COMMAND=/bin/bash",
        default_year=2026,
    )
    assert event.kind == "sudo_command"
    assert event.fields["invoker"] == "ubuntu"
    assert event.fields["target_user"] == "root"
    assert event.fields["command"] == "/bin/bash"


def test_parses_useradd_line():
    event = parse_line(
        "Jan 10 03:27:02 webserver useradd[2201]: new user: name=backdoor, UID=0, "
        "GID=0, home=/root, shell=/bin/bash",
        default_year=2026,
    )
    assert event.kind == "useradd"
    assert event.fields["name"] == "backdoor"
    assert event.fields["uid"] == 0


def test_parses_crontab_replace_line():
    event = parse_line(
        "Jan 10 03:28:11 webserver crontab[3301]: (root) REPLACE (root)", default_year=2026
    )
    assert event.kind == "crontab_replace"
    assert event.fields["user"] == "root"
    assert event.fields["action"] == "REPLACE"


def test_unrecognized_message_still_parses_as_other():
    event = parse_line("Jan 10 04:00:00 webserver systemd[1]: Started Session.", default_year=2026)
    assert event.kind == "other"


def test_ignores_blank_and_malformed_lines():
    assert parse_line("", default_year=2026) is None
    assert parse_line("   \n", default_year=2026) is None
    assert parse_line("not a valid syslog line at all", default_year=2026) is None


def test_parses_iso8601_timestamp():
    event = parse_line(
        "2026-01-10T03:22:10 webserver sshd[1201]: Failed password for root "
        "from 203.0.113.5 port 51501 ssh2"
    )
    assert event.timestamp == datetime(2026, 1, 10, 3, 22, 10)


def test_parse_file_reads_all_lines_in_order():
    events = parse_file(FIXTURES / "sample_auth.log", default_year=2026)
    assert len(events) == 12
    assert events == sorted(events, key=lambda e: e.timestamp)
    assert events[0].kind == "ssh_failed_password"
