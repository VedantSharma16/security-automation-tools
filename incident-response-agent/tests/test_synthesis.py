from ir_agent.models import ToolResult
from ir_agent.synthesis import synthesize_verdict


def test_known_exploited_cve_yields_critical():
    evidence = [
        ToolResult(
            tool="check_cve",
            tool_input="CVE-2021-44228",
            malicious=True,
            summary="Log4Shell",
            detail={"severity": "critical", "known_exploited": True},
        )
    ]
    verdict = synthesize_verdict("text", evidence, [], llm_backed=False)
    assert verdict.severity == "critical"
    assert any("Patch" in a for a in verdict.recommended_actions)


def test_no_evidence_yields_low_severity_and_generic_action():
    verdict = synthesize_verdict("Routine login.", [], [], llm_backed=False)
    assert verdict.severity == "low"
    assert verdict.confidence == 0.4
    assert "No known-malicious indicators" in verdict.recommended_actions[0]


def test_single_medium_confidence_ip_hit_yields_medium_severity():
    evidence = [
        ToolResult(
            tool="check_ip_reputation",
            tool_input="194.61.24.102",
            malicious=True,
            summary="scanning host",
            detail={"confidence": "medium"},
        )
    ]
    verdict = synthesize_verdict("text", evidence, [], llm_backed=False)
    assert verdict.severity == "medium"
    assert any("Block/monitor" in a for a in verdict.recommended_actions)


def test_confidence_increases_with_more_malicious_hits():
    one_hit = [
        ToolResult(tool="check_ip_reputation", tool_input="a", malicious=True, summary="", detail={"confidence": "low"})
    ]
    two_hits = one_hit + [
        ToolResult(tool="check_domain_reputation", tool_input="b", malicious=True, summary="", detail={"confidence": "low"})
    ]
    v1 = synthesize_verdict("t", one_hit, [], llm_backed=False)
    v2 = synthesize_verdict("t", two_hits, [], llm_backed=False)
    assert v2.confidence > v1.confidence
