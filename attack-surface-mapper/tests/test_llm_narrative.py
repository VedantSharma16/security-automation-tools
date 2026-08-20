from pathlib import Path

from asm.cve_matcher import load_rules, match_hosts
from asm.llm_narrative import TemplateNarrator, get_narrator
from asm.nmap_parser import parse_file
from asm.report import build_report
from asm.scoring import score_matches

EXAMPLES = Path(__file__).parent.parent / "examples"
DATA = Path(__file__).parent.parent / "data" / "cve_db.json"


def _sample_report():
    hosts = parse_file(EXAMPLES / "sample_scan.xml")
    rules = load_rules(DATA)
    matches = match_hosts(hosts, rules)
    scored = score_matches(matches)
    return build_report(EXAMPLES / "sample_scan.xml", hosts, scored)


def test_get_narrator_defaults_to_template_without_llm_flag():
    assert isinstance(get_narrator(use_llm=False), TemplateNarrator)


def test_get_narrator_falls_back_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert isinstance(get_narrator(use_llm=True), TemplateNarrator)


def test_template_narrator_reports_no_findings_message():
    report = build_report(EXAMPLES / "sample_scan.xml", [], [])
    narrative = TemplateNarrator().narrate(report)
    assert "No known CVE" in narrative


def test_template_narrator_mentions_exploit_and_confidence_context():
    report = _sample_report()
    narrative = TemplateNarrator().narrate(report)

    assert "Highest-priority exposure" in narrative
    assert "known public exploit" in narrative.lower() or "exploits" in narrative.lower()
    assert "Recommended focus" in narrative


def test_template_narrator_never_invents_hosts_not_in_report():
    report = _sample_report()
    narrative = TemplateNarrator().narrate(report)
    report_hosts = {f["host"] for f in report["findings"]}

    for token in narrative.split():
        if token.count(".") == 3 and token.replace(".", "").isdigit():
            assert token.rstrip(",():") in report_hosts
