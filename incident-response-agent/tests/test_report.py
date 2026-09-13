import json

from agent.engine import investigate
from agent.environment import Environment
from agent.planners import OfflinePlanner
from agent.report import to_json, to_markdown


def _malicious_report():
    env = Environment.load()
    alert = {"id": "ALRT-1", "title": "test alert", "host": "web01"}
    return investigate(alert, env, OfflinePlanner())


def test_to_markdown_contains_verdict_and_transcript() -> None:
    report = _malicious_report()
    md = to_markdown(report)

    assert "MALICIOUS" in md
    assert "CRITICAL" in md
    assert "search_logs" in md
    assert "## Investigation transcript" in md


def test_to_json_round_trips_transcript_length() -> None:
    report = _malicious_report()
    payload = json.loads(to_json(report))

    assert payload["verdict"] == "malicious"
    assert len(payload["transcript"]) == len(report.transcript)
    assert payload["transcript"][0]["tool"] == "search_logs"
    assert payload["transcript"][-1]["action"] == "final"


def test_to_markdown_flags_truncated_investigation() -> None:
    env = Environment.load()
    report = investigate({"host": "web01"}, env, OfflinePlanner(), max_turns=1)
    md = to_markdown(report)
    assert "truncated" in md.lower()
