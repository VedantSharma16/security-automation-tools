import unittest
from datetime import datetime, timedelta

from log_triage_agent.detectors import (
    detect_brute_force,
    detect_credential_success_after_failures,
    detect_off_hours_login,
    detect_password_spray,
    run_all_detectors,
)
from log_triage_agent.models import EventType, LogEvent

BASE_TIME = datetime(2026, 7, 10, 2, 0, 0)


def make_event(seconds_offset, event_type, username="admin", ip="203.0.113.5", port=51500):
    return LogEvent(
        timestamp=BASE_TIME + timedelta(seconds=seconds_offset),
        host="web01",
        process="sshd",
        pid=1000,
        event_type=event_type,
        username=username,
        source_ip=ip,
        port=port,
        raw_line="synthetic",
    )


class TestBruteForceDetector(unittest.TestCase):
    def test_flags_five_failures_within_window(self):
        events = [
            make_event(i * 10, EventType.FAILED_PASSWORD, username="root")
            for i in range(5)
        ]
        findings = detect_brute_force(events, threshold=5, window_minutes=10)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_type, "brute_force")
        self.assertEqual(findings[0].source_ip, "203.0.113.5")

    def test_does_not_flag_below_threshold(self):
        events = [make_event(i * 10, EventType.FAILED_PASSWORD) for i in range(3)]
        findings = detect_brute_force(events, threshold=5, window_minutes=10)
        self.assertEqual(findings, [])

    def test_does_not_flag_failures_spread_outside_window(self):
        events = [
            make_event(i * 600, EventType.FAILED_PASSWORD)  # 10 minutes apart each
            for i in range(5)
        ]
        findings = detect_brute_force(events, threshold=5, window_minutes=10)
        self.assertEqual(findings, [])


class TestPasswordSprayDetector(unittest.TestCase):
    def test_flags_many_distinct_usernames(self):
        users = ["admin", "root", "ubuntu", "oracle", "test"]
        events = [
            make_event(i * 10, EventType.INVALID_USER, username=user)
            for i, user in enumerate(users)
        ]
        findings = detect_password_spray(events, distinct_user_threshold=4)
        self.assertEqual(len(findings), 1)
        self.assertEqual(len(findings[0].metadata["distinct_users"]), 5)

    def test_does_not_flag_single_username_repeated(self):
        events = [
            make_event(i * 10, EventType.FAILED_PASSWORD, username="root")
            for i in range(5)
        ]
        findings = detect_password_spray(events, distinct_user_threshold=4)
        self.assertEqual(findings, [])


class TestCredentialSuccessAfterFailures(unittest.TestCase):
    def test_flags_success_preceded_by_failures(self):
        events = [make_event(i * 10, EventType.FAILED_PASSWORD, username="root") for i in range(3)]
        events.append(make_event(100, EventType.ACCEPTED_PASSWORD, username="root"))
        findings = detect_credential_success_after_failures(events, min_prior_failures=3)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].metadata["username"], "root")
        self.assertEqual(findings[0].metadata["prior_failures"], 3)

    def test_does_not_flag_clean_success(self):
        events = [make_event(0, EventType.ACCEPTED_PASSWORD, username="deploy", ip="10.0.0.15")]
        findings = detect_credential_success_after_failures(events, min_prior_failures=3)
        self.assertEqual(findings, [])

    def test_ignores_failures_outside_window(self):
        events = [
            make_event(i * 10, EventType.FAILED_PASSWORD, username="root")
            for i in range(3)
        ]
        # success arrives 20 minutes later, well outside a 10-minute window
        events.append(make_event(1200, EventType.ACCEPTED_PASSWORD, username="root"))
        findings = detect_credential_success_after_failures(events, min_prior_failures=3, window_minutes=10)
        self.assertEqual(findings, [])


class TestOffHoursLogin(unittest.TestCase):
    def test_flags_login_in_early_hours(self):
        events = [make_event(0, EventType.ACCEPTED_PASSWORD, username="root")]  # 02:00
        findings = detect_off_hours_login(events, start_hour=0, end_hour=5)
        self.assertEqual(len(findings), 1)

    def test_does_not_flag_business_hours_login(self):
        business_hours_event = LogEvent(
            timestamp=datetime(2026, 7, 10, 9, 0, 0),
            host="web01",
            process="sshd",
            pid=1000,
            event_type=EventType.ACCEPTED_PASSWORD,
            username="deploy",
            source_ip="10.0.0.15",
            port=42000,
            raw_line="synthetic",
        )
        findings = detect_off_hours_login([business_hours_event], start_hour=0, end_hour=5)
        self.assertEqual(findings, [])


class TestRunAllDetectors(unittest.TestCase):
    def test_composite_attack_scenario_triggers_multiple_findings(self):
        users = ["admin", "test", "oracle", "ubuntu"]
        events = [
            make_event(i * 10, EventType.INVALID_USER, username=user)
            for i, user in enumerate(users)
        ]
        events.append(make_event(40, EventType.FAILED_PASSWORD, username="root"))
        events.append(make_event(100, EventType.ACCEPTED_PASSWORD, username="root"))

        findings = run_all_detectors(events)
        finding_types = {f.finding_type for f in findings}
        self.assertIn("brute_force", finding_types)
        self.assertIn("password_spray", finding_types)
        self.assertIn("credential_success_after_failures", finding_types)
        self.assertIn("off_hours_login", finding_types)


if __name__ == "__main__":
    unittest.main()
