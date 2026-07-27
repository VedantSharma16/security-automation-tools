"""Exercises the live Claude tool-use loop against a scripted fake client,
so the multi-turn orchestration logic is covered without needing the
``anthropic`` package installed or a real API key.
"""

from types import SimpleNamespace

from soc_agent.agent import SecOpsAgent
from soc_agent.playbook import AlertCase


def _tool_use_block(name, input_, block_id):
    return SimpleNamespace(type="tool_use", name=name, input=input_, id=block_id)


class FakeMessages:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self._responses.pop(0)


class FakeClient:
    def __init__(self, responses):
        self.messages = FakeMessages(responses)


def _agent_with_fake_client(responses) -> SecOpsAgent:
    agent = SecOpsAgent(api_key=None)
    agent._client = FakeClient(responses)  # bypass real anthropic client construction
    return agent


def test_live_loop_calls_tools_then_submits_verdict():
    alert = AlertCase(alert_id="ALT-LIVE", description="test", dest_ip="203.0.113.55")

    turn1 = SimpleNamespace(
        content=[_tool_use_block("lookup_ioc_reputation", {"indicator": "203.0.113.55"}, "call_1")]
    )
    turn2 = SimpleNamespace(
        content=[
            _tool_use_block(
                "submit_verdict",
                {
                    "verdict": "malicious",
                    "confidence": "high",
                    "score": 90,
                    "evidence": ["203.0.113.55 is known-malicious C2 infrastructure."],
                    "recommended_actions": ["Block the indicator at the firewall."],
                },
                "call_2",
            )
        ]
    )

    agent = _agent_with_fake_client([turn1, turn2])
    report = agent.investigate(alert)

    assert report.mode == "live"
    assert report.verdict == "malicious"
    assert report.confidence == "high"
    assert len(report.trace) == 1
    assert report.trace[0].tool == "lookup_ioc_reputation"
    assert report.trace[0].result["verdict"] == "malicious"
    assert report.recommended_actions == ["Block the indicator at the firewall."]
    assert agent._client.messages.calls[0]["messages"][0]["role"] == "user"


def test_live_loop_falls_back_to_offline_when_budget_exhausted():
    alert = AlertCase(alert_id="ALT-STALL", description="test", hostname="db-primary.prod.internal")

    # The model keeps calling tools and never submits a verdict.
    stalling_turn = SimpleNamespace(
        content=[_tool_use_block("lookup_asset_criticality", {"hostname": "db-primary.prod.internal"}, "call_x")]
    )
    responses = [stalling_turn] * 8

    agent = _agent_with_fake_client(responses)
    report = agent.investigate(alert)

    assert report.mode == "offline"
    assert any("exceeded the max tool-call budget" in w for w in report.warnings)


def test_live_loop_falls_back_to_offline_on_client_error():
    alert = AlertCase(alert_id="ALT-ERR", description="test", hostname="db-primary.prod.internal")

    class ExplodingMessages:
        def create(self, **kwargs):
            raise RuntimeError("simulated API outage")

    agent = SecOpsAgent(api_key=None)
    agent._client = SimpleNamespace(messages=ExplodingMessages())

    report = agent.investigate(alert)

    assert report.mode == "offline"
    assert any("simulated API outage" in w for w in report.warnings)
