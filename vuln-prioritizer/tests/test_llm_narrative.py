from pathlib import Path

import pytest

from vuln_prioritizer.llm_narrative import TemplateNarrator, get_narrator
from vuln_prioritizer.pipeline import prioritize
from vuln_prioritizer.report import build_report

FIXTURES = Path(__file__).resolve().parent.parent / "examples"


def _report():
    scored = prioritize(FIXTURES / "sample_scan.csv", FIXTURES / "sample_assets.json")
    return build_report(FIXTURES / "sample_scan.csv", FIXTURES / "sample_assets.json", scored)


def test_template_narrator_mentions_top_finding():
    narrative = TemplateNarrator().narrate(_report())
    assert "CVE-2021-44228" in narrative
    assert "P1" in narrative


def test_template_narrator_handles_no_findings():
    report = _report()
    report["findings"] = []
    narrative = TemplateNarrator().narrate(report)
    assert "No vulnerabilities" in narrative


def test_template_narrator_mentions_kev_when_present():
    narrative = TemplateNarrator().narrate(_report())
    assert "Known Exploited" in narrative


def test_get_narrator_without_llm_flag_returns_template():
    assert isinstance(get_narrator(use_llm=False), TemplateNarrator)


def test_get_narrator_with_llm_but_no_api_key_falls_back(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    narrator = get_narrator(use_llm=True)
    assert isinstance(narrator, TemplateNarrator)
