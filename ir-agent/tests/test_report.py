import json

from ir_agent.agent import AgentResult, ToolCall
from ir_agent.report import to_json, to_markdown


def _sample_result():
    return AgentResult(
        mode="offline",
        severity="high",
        summary="Known-malicious IP observed brute-forcing SSH.",
        key_indicators=["91.219.236.18"],
        attack_techniques=["T1110"],
        recommended_actions=["Isolate the host."],
        transcript=[ToolCall(tool="extract_iocs", input={"text": "x" * 200}, output={"ips": []})],
    )


def test_to_json_round_trips():
    payload = json.loads(to_json(_sample_result()))
    assert payload["severity"] == "high"
    assert payload["key_indicators"] == ["91.219.236.18"]
    assert payload["transcript"][0]["tool"] == "extract_iocs"


def test_to_markdown_includes_key_sections():
    markdown = to_markdown(_sample_result())
    assert "HIGH" in markdown
    assert "91.219.236.18" in markdown
    assert "T1110" in markdown
    assert "Isolate the host." in markdown
    assert "Investigation transcript" in markdown


def test_to_markdown_truncates_long_transcript_input():
    markdown = to_markdown(_sample_result())
    assert "x" * 200 not in markdown
    assert "..." in markdown


def test_to_markdown_can_omit_transcript():
    markdown = to_markdown(_sample_result(), include_transcript=False)
    assert "Investigation transcript" not in markdown
