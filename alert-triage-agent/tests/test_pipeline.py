from pathlib import Path

import pytest

from triage_agent.models import Severity
from triage_agent.parser import parse_file
from triage_agent.pipeline import report_to_dict, report_to_json, run_pipeline
from triage_agent.rules import RuleEngine
from triage_agent.summarizer import AnthropicSummarizer, RuleBasedSummarizer

SAMPLE_LOG = Path(__file__).resolve().parent.parent / "sample_logs" / "auth_sample.log"


def test_run_pipeline_against_sample_log_with_default_rules():
    engine = RuleEngine.from_file()
    report = run_pipeline(SAMPLE_LOG, engine, RuleBasedSummarizer())

    assert report.stats["total_events"] > 0
    assert report.stats["total_findings"] > 0
    assert report.stats["severity_critical"] >= 1, "sample log contains mimikatz + wevtutil cl + encoded powershell"
    assert "Scanned" in report.summary


def test_run_pipeline_no_matches_produces_clean_report(tmp_path):
    logfile = tmp_path / "clean.log"
    logfile.write_text("everything is fine\nnothing to see here\n")

    engine = RuleEngine.from_file()
    report = run_pipeline(logfile, engine, RuleBasedSummarizer())

    assert report.stats["total_findings"] == 0
    assert "No rule matches" in report.summary


def test_run_pipeline_missing_file_raises():
    engine = RuleEngine.from_file()
    with pytest.raises(FileNotFoundError):
        run_pipeline("/nonexistent/path.log", engine, RuleBasedSummarizer())


def test_report_to_dict_roundtrips_findings():
    engine = RuleEngine.from_file()
    report = run_pipeline(SAMPLE_LOG, engine, RuleBasedSummarizer())
    data = report_to_dict(report)

    assert data["generated_by"] == "rule-based"
    assert len(data["findings"]) == report.stats["total_findings"]
    assert all(f["severity"] in Severity.__members__ for f in data["findings"])


def test_report_to_json_is_valid_json():
    import json

    engine = RuleEngine.from_file()
    report = run_pipeline(SAMPLE_LOG, engine, RuleBasedSummarizer())
    parsed = json.loads(report_to_json(report))
    assert parsed["stats"]["total_findings"] == report.stats["total_findings"]


def test_anthropic_summarizer_requires_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    engine = RuleEngine.from_file()
    findings = engine.scan(parse_file(SAMPLE_LOG))

    with pytest.raises(RuntimeError):
        AnthropicSummarizer().summarize(findings, total_events=1)
