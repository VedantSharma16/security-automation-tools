import pytest

from agentic_soc.transcript import AgentStep, AgentTranscript, Verdict


def test_verdict_rejects_invalid_label():
    with pytest.raises(ValueError):
        Verdict(verdict="unknown", confidence=0.5, reasoning="x")


def test_verdict_clamps_confidence_to_unit_interval():
    assert Verdict(verdict="benign", confidence=1.5, reasoning="x").confidence == 1.0
    assert Verdict(verdict="benign", confidence=-0.5, reasoning="x").confidence == 0.0


def test_transcript_to_dict_round_trips_fields():
    step = AgentStep(thought="checking", tool="lookup_ioc", tool_input={"indicator": "1.2.3.4"}, observation={"matched": False})
    verdict = Verdict(verdict="benign", confidence=0.7, reasoning="nothing found", recommended_actions=["close it"])
    transcript = AgentTranscript(alert_text="alert", steps=[step], verdict=verdict, llm_backed=False)

    as_dict = transcript.to_dict()
    assert as_dict["steps_used"] == 1
    assert as_dict["steps"][0]["tool"] == "lookup_ioc"
    assert as_dict["verdict"]["verdict"] == "benign"
    assert as_dict["llm_backed"] is False
