from log_sentinel.parser import EventType, parse_file, parse_line


def test_parse_failed_password():
    line = "Jul 14 03:14:17 web01 sshd[1025]: Failed password for root from 203.0.113.55 port 51505 ssh2"
    entry = parse_line(line, year=2026)
    assert entry is not None
    assert entry.event == EventType.FAILED_PASSWORD
    assert entry.user == "root"
    assert entry.source_ip == "203.0.113.55"
    assert entry.port == 51505
    assert entry.timestamp.month == 7
    assert entry.timestamp.day == 14
    assert entry.timestamp.hour == 3


def test_parse_failed_invalid_user():
    line = (
        "Jul 14 03:14:02 web01 sshd[1021]: Failed password for invalid user admin "
        "from 203.0.113.55 port 51501 ssh2"
    )
    entry = parse_line(line, year=2026)
    assert entry is not None
    assert entry.event == EventType.FAILED_INVALID_USER
    assert entry.user == "admin"


def test_parse_invalid_user_no_port():
    line = "Jul 14 03:14:01 web01 sshd[1021]: Invalid user admin from 203.0.113.55"
    entry = parse_line(line, year=2026)
    assert entry is not None
    assert entry.event == EventType.INVALID_USER
    assert entry.user == "admin"
    assert entry.port is None


def test_parse_accepted_publickey():
    line = "Jul 14 08:02:11 web01 sshd[2051]: Accepted publickey for deploy from 198.51.100.20 port 55210 ssh2"
    entry = parse_line(line, year=2026)
    assert entry is not None
    assert entry.event == EventType.ACCEPTED
    assert entry.user == "deploy"
    assert entry.source_ip == "198.51.100.20"


def test_parse_ignores_unrelated_lines():
    line = "Jul 14 03:14:26 web01 sshd[1028]: pam_unix(sshd:session): session opened for user root by (uid=0)"
    assert parse_line(line, year=2026) is None


def test_parse_file(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        "Jul 14 03:14:17 web01 sshd[1025]: Failed password for root from 203.0.113.55 port 51505 ssh2\n"
        "not a log line at all\n"
        "Jul 14 08:02:11 web01 sshd[2051]: Accepted publickey for deploy from 198.51.100.20 port 55210 ssh2\n"
    )
    entries = parse_file(log, year=2026)
    assert len(entries) == 2
    assert entries[0].event == EventType.FAILED_PASSWORD
    assert entries[1].event == EventType.ACCEPTED
