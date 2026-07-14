from datetime import datetime, timedelta

from log_sentinel.detector import Finding, FindingType, Severity
from log_sentinel.report import (
    AnthropicReportGenerator,
    TemplateReportGenerator,
    findings_to_dicts,
    get_report_generator,
)

NOW = datetime(2026, 7, 14, 3, 0, 0)


def make_finding(**overrides):
    defaults = dict(
        type=FindingType.BRUTE_FORCE,
        severity=Severity.HIGH,
        source_ip="203.0.113.55",
        users=["root"],
        count=5,
        first_seen=NOW,
        last_seen=NOW + timedelta(seconds=20),
        description="5 failed SSH authentication attempts from 203.0.113.55.",
        mitre_technique="T1110 (Brute Force)",
        evidence=["<raw log line>"],
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_template_report_no_findings():
    report = TemplateReportGenerator().generate([], source_label="auth.log")
    assert "No suspicious activity detected" in report


def test_template_report_includes_finding_details():
    finding = make_finding()
    report = TemplateReportGenerator().generate([finding], source_label="auth.log")
    assert "BRUTE_FORCE" in report
    assert "203.0.113.55" in report
    assert "T1110" in report
    assert "root" in report
    assert "Recommended action" in report


def test_template_report_summarizes_severity_counts():
    findings = [
        make_finding(severity=Severity.CRITICAL),
        make_finding(severity=Severity.LOW, type=FindingType.ANOMALOUS_LOGIN_TIME, mitre_technique=None),
    ]
    report = TemplateReportGenerator().generate(findings, source_label="auth.log")
    assert "2 finding(s)" in report
    assert "1 critical" in report
    assert "1 low" in report


def test_findings_to_dicts_is_json_serializable():
    import json

    data = findings_to_dicts([make_finding()])
    serialized = json.dumps(data)
    assert "BRUTE_FORCE" in serialized


def test_get_report_generator_selects_backend():
    assert isinstance(get_report_generator(use_llm=False), TemplateReportGenerator)
    assert isinstance(get_report_generator(use_llm=True), AnthropicReportGenerator)


def test_anthropic_generator_falls_back_without_package_or_key(monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    generator = AnthropicReportGenerator()
    report = generator.generate([make_finding()], source_label="auth.log")
    # Whether it falls back due to a missing package or a missing key, the
    # result must still be a usable report (never a crash / empty string).
    assert "BRUTE_FORCE" in report
    assert capsys.readouterr().err  # a warning was printed explaining the fallback
