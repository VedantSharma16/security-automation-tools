import sys

from soc_agent.agent import investigate
from tests.fake_anthropic import FakeBlock, FakeResponse, make_fake_anthropic_module

MALICIOUS_ALERT = (
    "powershell.exe spawned by winword.exe with an encoded command line beaconed "
    "to update-service-cdn.net (45.155.205.38) and 185.220.101.1."
)

BENIGN_ALERT = "User bob authenticated via SSH from 8.8.8.8 to restart the nginx service."


def test_offline_agent_flags_malicious_alert_as_critical(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = investigate(MALICIOUS_ALERT, api_key=None)

    assert result.llm_backed is False
    assert result.verdict == "malicious"
    assert result.severity == "critical"
    assert len(result.steps) > 0
    actions = " ".join(result.recommended_actions)
    assert "Isolate" in actions


def test_offline_agent_flags_benign_alert_as_low_severity(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = investigate(BENIGN_ALERT, api_key=None)

    assert result.llm_backed is False
    assert result.verdict == "benign"
    assert result.severity == "low"


def test_offline_agent_handles_no_indicators(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = investigate("Nothing of note happened today.", api_key=None)

    assert result.verdict == "inconclusive"
    assert len(result.steps) == 1


def test_investigate_falls_back_to_offline_when_key_present_but_sdk_missing(monkeypatch):
    monkeypatch.delitem(sys.modules, "anthropic", raising=False)
    result = investigate(MALICIOUS_ALERT, api_key="sk-fake-but-no-sdk")
    assert result.llm_backed is False


def test_investigate_uses_live_agent_when_key_and_sdk_available(monkeypatch):
    tool_call = FakeResponse(
        content=[
            FakeBlock(type="text", text="Checking the domain."),
            FakeBlock(
                type="tool_use",
                name="lookup_domain_reputation",
                input={"domain": "update-service-cdn.net"},
                id="tu_1",
            ),
        ]
    )
    final = FakeResponse(
        content=[
            FakeBlock(
                type="text",
                text=(
                    '{"verdict": "malicious", "severity": "high", "confidence": "high", '
                    '"summary": "Lookalike update domain.", "recommended_actions": ["Block domain"]}'
                ),
            )
        ]
    )
    monkeypatch.setitem(sys.modules, "anthropic", make_fake_anthropic_module([tool_call, final]))

    result = investigate(MALICIOUS_ALERT, api_key="sk-fake")

    assert result.llm_backed is True
    assert result.verdict == "malicious"
    assert result.recommended_actions == ["Block domain"]
    assert len(result.steps) == 1
    assert result.steps[0].action == "lookup_domain_reputation"


def test_investigate_synthesizes_verdict_when_live_agent_exhausts_steps(monkeypatch):
    def endless():
        return FakeResponse(
            content=[
                FakeBlock(type="tool_use", name="lookup_ip_reputation", input={"ip": "185.220.101.1"}, id="tu")
            ]
        )

    monkeypatch.setitem(sys.modules, "anthropic", make_fake_anthropic_module([endless() for _ in range(2)]))

    result = investigate(MALICIOUS_ALERT, api_key="sk-fake", max_steps=2)

    assert result.llm_backed is True
    assert result.verdict == "malicious"
    assert "step budget exhausted" in result.summary
