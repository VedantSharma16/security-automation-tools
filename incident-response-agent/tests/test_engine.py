import pytest

from agent.engine import FinalStep, ToolCallStep, Turn, investigate
from agent.environment import Environment
from agent.planners import OfflinePlanner


@pytest.fixture
def env() -> Environment:
    return Environment.load()


def test_investigate_malicious_scenario(env: Environment) -> None:
    report = investigate({"host": "web01"}, env, OfflinePlanner())

    assert report.verdict == "malicious"
    assert report.severity == "critical"
    assert not report.truncated

    tool_names = [t.name for t in report.transcript if t.action == "tool_call"]
    assert tool_names == [
        "search_logs",
        "lookup_ioc",
        "get_process_list",
        "get_process_detail",
        "lookup_ioc",
    ]
    assert report.transcript[-1].action == "final"


def test_investigate_benign_scenario(env: Environment) -> None:
    report = investigate({"host": "ws-jdoe"}, env, OfflinePlanner())

    assert report.verdict == "benign"
    assert report.severity == "informational"
    assert not report.truncated

    tool_names = [t.name for t in report.transcript if t.action == "tool_call"]
    assert tool_names == ["search_logs", "get_process_list"]


def test_investigate_truncates_when_max_turns_too_low(env: Environment) -> None:
    report = investigate({"host": "web01"}, env, OfflinePlanner(), max_turns=2)

    assert report.truncated is True
    assert report.verdict == "inconclusive"
    assert report.severity == "unknown"
    assert len(report.transcript) == 2


class _FixedPlanner:
    """A minimal stub planner used to test the loop's tool-error handling."""

    def __init__(self, steps):
        self._steps = list(steps)

    def next_step(self, alert, transcript):
        return self._steps.pop(0)


def test_investigate_records_tool_errors_without_crashing(env: Environment) -> None:
    planner = _FixedPlanner(
        [
            ToolCallStep(name="get_process_list", arguments={"host": "no-such-host"}, reasoning="oops"),
            FinalStep(verdict="inconclusive", severity="unknown", summary="gave up"),
        ]
    )
    report = investigate({"host": "web01"}, env, planner)

    assert report.transcript[0].error is not None
    assert "no-such-host" in report.transcript[0].error
    assert report.verdict == "inconclusive"
