import unittest
from unittest.mock import patch

from log_triage_agent.knowledge_base import AttackKnowledgeBase
from log_triage_agent.models import Finding, Severity
from log_triage_agent.reporter import (
    TemplateNarrator,
    generate_report,
    get_default_narrator,
)

SAMPLE_FINDING = Finding(
    finding_type="brute_force",
    severity=Severity.HIGH,
    source_ip="203.0.113.5",
    summary="5 failed login attempts from 203.0.113.5 within 10 minutes.",
    events=[object()] * 5,
)


class TestTemplateNarrator(unittest.TestCase):
    def test_includes_severity_and_technique_ids(self):
        kb = AttackKnowledgeBase()
        techniques = kb.retrieve_for_finding(SAMPLE_FINDING.finding_type, SAMPLE_FINDING.summary)
        narrative = TemplateNarrator().narrate(SAMPLE_FINDING, techniques)
        self.assertIn("HIGH", narrative)
        self.assertIn("T1110", narrative)

    def test_handles_no_matching_techniques(self):
        narrative = TemplateNarrator().narrate(SAMPLE_FINDING, [])
        self.assertIn("HIGH", narrative)


class TestGenerateReport(unittest.TestCase):
    def test_empty_findings_reports_clean(self):
        report = generate_report([])
        self.assertIn("No suspicious activity", report)

    def test_report_contains_expected_sections(self):
        report = generate_report([SAMPLE_FINDING], narrator=TemplateNarrator())
        self.assertIn("Brute Force", report)
        self.assertIn("203.0.113.5", report)
        self.assertIn("MITRE ATT&CK mapping", report)
        self.assertIn("Recommended actions", report)

    def test_findings_are_ordered_by_severity(self):
        low = Finding(
            finding_type="off_hours_login",
            severity=Severity.LOW,
            source_ip="10.0.0.15",
            summary="Off hours login",
        )
        critical = Finding(
            finding_type="credential_success_after_failures",
            severity=Severity.CRITICAL,
            source_ip="203.0.113.5",
            summary="Compromised account",
        )
        report = generate_report([low, critical], narrator=TemplateNarrator())
        self.assertLess(report.index("CRITICAL"), report.index("LOW"))


class TestGetDefaultNarrator(unittest.TestCase):
    def test_falls_back_to_template_without_api_key(self):
        with patch.dict("os.environ", {}, clear=True):
            narrator = get_default_narrator()
            self.assertIsInstance(narrator, TemplateNarrator)

    def test_falls_back_to_template_if_sdk_missing(self):
        # anthropic isn't installed in this environment, so even with a key
        # set, construction should fail gracefully and fall back.
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-test-key"}):
            narrator = get_default_narrator()
            self.assertIsInstance(narrator, TemplateNarrator)


if __name__ == "__main__":
    unittest.main()
