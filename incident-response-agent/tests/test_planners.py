import pytest

from agent.engine import FinalStep, Turn
from agent.planners import ClaudePlanner, OfflinePlanner, _extract_external_ips, _is_internal, get_planner


def test_is_internal_true_for_lab_ranges() -> None:
    assert _is_internal("10.0.0.15")
    assert _is_internal("192.168.1.1")
    assert _is_internal("127.0.0.1")


def test_is_internal_false_for_documentation_range() -> None:
    # RFC 5737 TEST-NET-3, used in the fixtures to stand in for "the internet".
    assert not _is_internal("203.0.113.55")


def test_extract_external_ips_dedupes_and_filters() -> None:
    lines = [
        "... from 203.0.113.55 port 1",
        "... from 203.0.113.55 port 2",
        "... internal hop 10.0.0.15",
    ]
    assert _extract_external_ips(lines) == ["203.0.113.55"]


def test_offline_planner_first_step_is_search_logs() -> None:
    planner = OfflinePlanner()
    step = planner.next_step({"host": "web01"}, [])
    assert step.name == "search_logs"
    assert step.arguments == {"host": "web01"}


def test_offline_planner_pivots_to_ioc_lookup_after_finding_external_ip() -> None:
    planner = OfflinePlanner()
    transcript = [
        Turn(
            step_number=1,
            reasoning="",
            action="tool_call",
            name="search_logs",
            arguments={"host": "web01"},
            observation={
                "host": "web01",
                "query": None,
                "count": 1,
                "matched_lines": ["... Failed password for root from 203.0.113.55 port 1 ssh2"],
            },
        )
    ]
    step = planner.next_step({"host": "web01"}, transcript)
    assert step.name == "lookup_ioc"
    assert step.arguments == {"indicator": "203.0.113.55"}


def test_offline_planner_never_repeats_a_tool_call_pointlessly() -> None:
    """Feeding it a fully-explored transcript should always reach a final step."""
    planner = OfflinePlanner()
    from agent.environment import Environment
    from agent.engine import investigate

    env = Environment.load()
    report = investigate({"host": "web01"}, env, planner, max_turns=8)
    assert not report.truncated
    assert report.verdict in {"malicious", "benign", "inconclusive"}


def test_get_planner_falls_back_to_offline_without_api_key(monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    planner = get_planner(use_llm=True)
    assert isinstance(planner, OfflinePlanner)


def test_get_planner_offline_by_default() -> None:
    assert isinstance(get_planner(use_llm=False), OfflinePlanner)


def test_claude_planner_raises_without_client() -> None:
    planner = ClaudePlanner(api_key=None)
    with pytest.raises(RuntimeError):
        planner.next_step({"host": "web01"}, [])


def test_claude_planner_parses_final_json_response() -> None:
    text = '{"verdict": "malicious", "severity": "high", "summary": "x"}'
    step = ClaudePlanner._parse_final(text)
    assert isinstance(step, FinalStep)
    assert step.verdict == "malicious"


def test_claude_planner_falls_back_on_unparseable_response() -> None:
    step = ClaudePlanner._parse_final("not json")
    assert step.verdict == "inconclusive"
    assert step.summary == "not json"
