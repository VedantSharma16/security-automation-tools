from pathlib import Path

from ir_agent.agent import run_agent, run_offline

SAMPLE_INCIDENT = (Path(__file__).resolve().parent.parent / "examples" / "sample_incident.txt").read_text()


def test_offline_loop_investigates_every_entity_before_finishing():
    verdict = run_offline(SAMPLE_INCIDENT)

    tools_called = {step.tool for step in verdict.trace}
    assert {"check_cve", "check_ip_reputation", "check_domain_reputation", "lookup_attack_technique"} <= tools_called
    assert verdict.trace[-1].tool == "finish"
    assert verdict.llm_backed is False


def test_offline_loop_flags_known_bad_indicators_as_critical():
    verdict = run_offline(SAMPLE_INCIDENT)
    # exploited Log4Shell CVE + high-confidence C2 IP + high-confidence C2 domain
    assert verdict.severity in ("critical", "high")
    assert any("45.155.205.28" in a or "block" in a.lower() for a in verdict.recommended_actions)


def test_offline_loop_is_deterministic():
    v1 = run_offline(SAMPLE_INCIDENT)
    v2 = run_offline(SAMPLE_INCIDENT)
    assert v1.to_dict() == v2.to_dict()


def test_offline_loop_respects_max_steps_and_reports_truncation():
    text = " ".join(f"10.0.0.{i}" for i in range(1, 10))  # 9 distinct IPs
    verdict = run_offline(text, max_steps=3)

    action_steps = [s for s in verdict.trace if s.tool != "finish"]
    assert len(action_steps) == 3
    assert "max_steps" in verdict.trace[-1].thought


def test_offline_loop_handles_incident_with_no_entities():
    verdict = run_offline("Routine password reset ticket, user-initiated, nothing anomalous.")
    assert verdict.severity == "low"
    # still runs the ATT&CK keyword lookup + finish even with no extracted entities
    assert [s.tool for s in verdict.trace] == ["lookup_attack_technique", "finish"]


def test_run_agent_falls_back_to_offline_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    verdict = run_agent(SAMPLE_INCIDENT, api_key=None)
    assert verdict.llm_backed is False
