from types import SimpleNamespace

from soc_orchestrator.synthesis import build_narrative, synthesize
from soc_orchestrator.tools import ToolResult


def _case(description="incident"):
    return SimpleNamespace(case_dir="/cases/1", incident_description=description)


def test_synthesize_takes_the_highest_severity_across_ok_tools():
    results = [
        ToolResult(tool="run_log_triage", ok=True, severity="MEDIUM", data={}),
        ToolResult(tool="run_ioc_triage", ok=True, severity="critical", data={}),
        ToolResult(tool="run_process_hunt", ok=True, severity="low", data={}),
    ]
    report = synthesize(_case(), results, narrative=None, llm_backed=False, generated_at="t")
    assert report.overall_severity == "critical"


def test_synthesize_ignores_failed_tools_for_severity():
    results = [
        ToolResult(tool="run_log_triage", ok=False, severity="critical", error="boom", data={}),
        ToolResult(tool="run_process_hunt", ok=True, severity="low", data={}),
    ]
    report = synthesize(_case(), results, narrative=None, llm_backed=False, generated_at="t")
    assert report.overall_severity == "low"


def test_synthesize_no_results_is_none_severity_with_default_action():
    report = synthesize(_case(), [], narrative=None, llm_backed=False, generated_at="t")
    assert report.overall_severity == "none"
    assert report.recommended_actions == [
        "No immediate action required based on current evidence; continue routine monitoring."
    ]


def test_risk_score_sums_weights_and_caps_at_100():
    results = [ToolResult(tool="a", ok=True, severity="critical", data={}) for _ in range(3)]
    report = synthesize(_case(), results, narrative=None, llm_backed=False, generated_at="t")
    assert report.risk_score == 100


def test_recommended_actions_reflect_brute_force_finding():
    results = [
        ToolResult(
            tool="run_log_triage",
            ok=True,
            severity="high",
            data={"findings": [{"type": "brute_force"}]},
        )
    ]
    report = synthesize(_case(), results, narrative=None, llm_backed=False, generated_at="t")
    assert any("Rotate credentials" in a for a in report.recommended_actions)


def test_recommended_actions_flag_known_malicious_iocs_by_value():
    results = [
        ToolResult(
            tool="run_ioc_triage",
            ok=True,
            severity="critical",
            data={"enrichment": [{"value": "evil.example.com", "is_known_malicious": True}]},
        )
    ]
    report = synthesize(_case(), results, narrative=None, llm_backed=False, generated_at="t")
    assert any("evil.example.com" in a for a in report.recommended_actions)


def test_recommended_actions_suggest_isolation_on_live_process_findings():
    results = [
        ToolResult(
            tool="run_process_hunt",
            ok=True,
            severity="high",
            data={"finding_count": 1},
        )
    ]
    report = synthesize(_case(), results, narrative=None, llm_backed=False, generated_at="t")
    assert any("Isolate this host" in a for a in report.recommended_actions)


def test_mitre_techniques_merged_and_deduplicated_across_tools():
    results = [
        ToolResult(
            tool="run_process_hunt",
            ok=True,
            severity="high",
            data={
                "findings": [
                    {"mitre_technique": "T1059", "mitre_tactic": "Execution"},
                    {"mitre_technique": "T1059", "mitre_tactic": "Execution"},
                ]
            },
        ),
        ToolResult(
            tool="run_ioc_triage",
            ok=True,
            severity="high",
            data={"matched_techniques": [{"id": "T1071", "tactic": "C2", "name": "App Layer Protocol"}]},
        ),
    ]
    report = synthesize(_case(), results, narrative=None, llm_backed=False, generated_at="t")
    ids = {t["id"] for t in report.mitre_techniques}
    assert ids == {"T1059", "T1071"}


def test_build_narrative_lists_failed_tools_separately():
    results = [
        ToolResult(tool="run_log_triage", ok=True, severity="low", summary="fine", data={}),
        ToolResult(tool="run_ioc_triage", ok=False, error="no such file", data={}),
    ]
    narrative = build_narrative(results, overall_severity="low")
    assert "run_log_triage: fine" in narrative
    assert "run_ioc_triage could not run: no such file" in narrative


def test_synthesize_uses_provided_narrative_when_given():
    report = synthesize(_case(), [], narrative="custom narrative", llm_backed=True, generated_at="t")
    assert report.narrative == "custom narrative"
    assert report.llm_backed is True


def test_report_to_dict_serializes_tool_results():
    results = [ToolResult(tool="a", ok=True, severity="low", data={"k": "v"})]
    report = synthesize(_case(), results, narrative="n", llm_backed=False, generated_at="t")
    d = report.to_dict()
    assert d["tools_invoked"] == [
        {"tool": "a", "ok": True, "severity": "low", "summary": "", "data": {"k": "v"}, "error": None}
    ]
