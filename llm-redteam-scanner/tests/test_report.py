import json

from llm_redteam.attacks import ATTACKS
from llm_redteam.judge import ResponseJudge
from llm_redteam.report import build_report, compute_severity, render_text
from llm_redteam.scanner import run_scan
from llm_redteam.target import DemoHardenedAssistant, DemoVulnerableAssistant


def _offline_judge():
    return ResponseJudge(api_key=None)


def test_severity_is_critical_when_secret_leaked():
    findings = run_scan(DemoVulnerableAssistant(), attacks=ATTACKS, judge=_offline_judge())
    report = build_report("demo-vulnerable", findings)
    assert report.severity == "critical"
    assert report.vulnerable_count == len(ATTACKS)


def test_severity_is_low_when_nothing_found():
    findings = run_scan(DemoHardenedAssistant(), attacks=ATTACKS, judge=_offline_judge())
    report = build_report("demo-hardened", findings)
    assert report.severity == "low"
    assert report.vulnerable_count == 0


def test_compute_severity_thresholds():
    class _Verdict:
        def __init__(self, vulnerable, basis):
            self.vulnerable = vulnerable
            self.basis = basis

    class _Finding:
        def __init__(self, vulnerable, basis):
            self.verdict = _Verdict(vulnerable, basis)

    assert compute_severity([]) == "low"
    assert compute_severity([_Finding(False, "refusal_detected")]) == "low"
    assert compute_severity([_Finding(True, "compliance_heuristic")]) == "medium"
    assert (
        compute_severity(
            [
                _Finding(True, "compliance_heuristic"),
                _Finding(True, "compliance_heuristic"),
                _Finding(True, "compliance_heuristic"),
            ]
        )
        == "high"
    )
    assert compute_severity([_Finding(True, "secret_leak")]) == "critical"


def test_report_to_dict_and_json_round_trip():
    findings = run_scan(DemoVulnerableAssistant(), attacks=ATTACKS, judge=_offline_judge())
    report = build_report("demo-vulnerable", findings)
    payload = json.loads(report.to_json())
    assert payload["severity"] == "critical"
    assert len(payload["findings"]) == len(ATTACKS)
    assert payload["findings"][0]["attack_id"] == findings[0].attack.id


def test_render_text_lists_every_attack():
    findings = run_scan(DemoVulnerableAssistant(), attacks=ATTACKS, judge=_offline_judge())
    report = build_report("demo-vulnerable", findings)
    text = render_text(report)
    assert "Overall risk: CRITICAL" in text
    for attack in ATTACKS:
        assert attack.id in text
    assert text.count("VULNERABLE") == len(ATTACKS)
