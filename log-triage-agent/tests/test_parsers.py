import unittest

from log_triage_agent.models import EventType
from log_triage_agent.parsers import parse_file, parse_line


class TestParseLine(unittest.TestCase):
    def test_parses_invalid_user_failure(self):
        event = parse_line(
            "Jul 10 02:10:01 web01 sshd[10234]: Failed password for invalid user "
            "admin from 203.0.113.5 port 51501 ssh2",
            year=2026,
        )
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, EventType.INVALID_USER)
        self.assertEqual(event.username, "admin")
        self.assertEqual(event.source_ip, "203.0.113.5")
        self.assertEqual(event.port, 51501)
        self.assertEqual(event.host, "web01")
        self.assertEqual(event.pid, 10234)
        self.assertEqual((event.timestamp.month, event.timestamp.day), (7, 10))
        self.assertEqual(event.timestamp.hour, 2)

    def test_parses_valid_user_failure(self):
        event = parse_line(
            "Jul 10 02:10:49 web01 sshd[10238]: Failed password for root from "
            "203.0.113.5 port 51509 ssh2",
            year=2026,
        )
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, EventType.FAILED_PASSWORD)
        self.assertEqual(event.username, "root")

    def test_parses_accepted_password(self):
        event = parse_line(
            "Jul 10 02:14:50 web01 sshd[10245]: Accepted password for root from "
            "203.0.113.5 port 51600 ssh2",
            year=2026,
        )
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, EventType.ACCEPTED_PASSWORD)

    def test_ignores_unrelated_lines(self):
        self.assertIsNone(parse_line("Jul 10 02:14:50 web01 sshd[10245]: Connection closed", year=2026))
        self.assertIsNone(parse_line("", year=2026))
        self.assertIsNone(parse_line("not a log line at all", year=2026))

    def test_defaults_to_current_year_when_not_specified(self):
        from datetime import datetime

        event = parse_line(
            "Jul 10 02:10:01 web01 sshd[10234]: Accepted password for root from "
            "203.0.113.5 port 51501 ssh2"
        )
        self.assertEqual(event.timestamp.year, datetime.now().year)


class TestParseFile(unittest.TestCase):
    def test_parses_sample_log(self):
        events = parse_file("data/sample_auth.log", year=2026)
        # 9 lines in the fixture, all of which are recognized event lines.
        self.assertEqual(len(events), 9)
        ips = {e.source_ip for e in events}
        self.assertIn("203.0.113.5", ips)
        self.assertIn("10.0.0.15", ips)


if __name__ == "__main__":
    unittest.main()
