from dataclasses import dataclass, field

from codesec_agent.agent import CodeSecurityAgent

VULNERABLE_SNIPPET = "import os\ndef f(x):\n    os.system(x)\n"
CLEAN_SNIPPET = "def add(a, b):\n    return a + b\n"


def _project(tmp_path):
    (tmp_path / "app.py").write_text(VULNERABLE_SNIPPET)
    (tmp_path / "safe.py").write_text(CLEAN_SNIPPET)
    return tmp_path


# -- fakes standing in for the Anthropic SDK's response shape --------------


@dataclass
class _FakeBlock:
    type: str
    text: str = ""
    name: str = ""
    input: dict = field(default_factory=dict)
    id: str = "tool_1"


@dataclass
class _FakeResponse:
    content: list
    stop_reason: str


class FakeClient:
    """Stands in for anthropic.Anthropic: scripted `.messages.create` responses."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    class _Messages:
        def __init__(self, outer):
            self._outer = outer

        def create(self, **kwargs):
            self._outer.calls.append(kwargs)
            return self._outer._responses.pop(0)

    @property
    def messages(self):
        return self._Messages(self)


def test_offline_mode_is_not_live_and_grounds_findings_in_scanner(tmp_path):
    project = _project(tmp_path)
    agent = CodeSecurityAgent(api_key=None)

    report = agent.review(str(project))

    assert agent.is_live is False
    assert report.llm_backed is False
    assert report.tool_calls == []
    assert "offline heuristic summary" in report.narrative
    assert len(report.findings) == 1
    assert report.findings[0].rule_id == "command-injection"
    assert report.severity_counts["high"] == 1
    assert sorted(report.files_scanned) == ["app.py", "safe.py"]


def test_offline_narrative_handles_zero_findings(tmp_path):
    (tmp_path / "safe.py").write_text(CLEAN_SNIPPET)
    report = CodeSecurityAgent(api_key=None).review(str(tmp_path))
    assert "No findings" in report.narrative


def test_agent_report_to_dict_round_trips_key_fields(tmp_path):
    project = _project(tmp_path)
    report = CodeSecurityAgent(api_key=None).review(str(project))
    d = report.to_dict()
    assert d["llm_backed"] is False
    assert d["findings"][0]["rule_id"] == "command-injection"
    assert isinstance(d["severity_counts"], dict)


def test_live_loop_executes_tool_calls_and_returns_final_text(tmp_path):
    project = _project(tmp_path)

    list_files_call = _FakeResponse(
        content=[_FakeBlock(type="tool_use", name="list_python_files", input={}, id="t1")],
        stop_reason="tool_use",
    )
    run_rules_call = _FakeResponse(
        content=[_FakeBlock(type="tool_use", name="run_static_rules", input={"path": "app.py"}, id="t2")],
        stop_reason="tool_use",
    )
    final_answer = _FakeResponse(
        content=[_FakeBlock(type="text", text="app.py calls os.system with unsanitized input.")],
        stop_reason="end_turn",
    )
    client = FakeClient([list_files_call, run_rules_call, final_answer])

    agent = CodeSecurityAgent(client=client, max_turns=5)
    report = agent.review(str(project))

    assert agent.is_live is True
    assert report.llm_backed is True
    assert report.narrative == "app.py calls os.system with unsanitized input."
    assert [c["name"] for c in report.tool_calls] == ["list_python_files", "run_static_rules"]
    # findings still come from our own scan, not from the model's tool calls
    assert len(report.findings) == 1


def test_live_loop_stops_after_max_turns_and_asks_for_final_summary(tmp_path):
    project = _project(tmp_path)

    def endless_tool_call():
        return _FakeResponse(
            content=[_FakeBlock(type="tool_use", name="list_python_files", input={}, id="t")],
            stop_reason="tool_use",
        )

    max_turns = 3
    responses = [endless_tool_call() for _ in range(max_turns)]
    responses.append(
        _FakeResponse(content=[_FakeBlock(type="text", text="Ran out of turns; summarizing so far.")], stop_reason="end_turn")
    )
    client = FakeClient(responses)

    agent = CodeSecurityAgent(client=client, max_turns=max_turns)
    report = agent.review(str(project))

    assert report.narrative == "Ran out of turns; summarizing so far."
    assert len(report.tool_calls) == max_turns
    # the forced final call must not offer tools again
    assert "tools" not in client.calls[-1]


def test_live_loop_falls_back_to_offline_on_client_exception(tmp_path):
    project = _project(tmp_path)

    class ExplodingClient:
        @property
        def messages(self):
            raise RuntimeError("boom")

    agent = CodeSecurityAgent(client=ExplodingClient())
    report = agent.review(str(project))

    assert report.llm_backed is True  # client was configured...
    assert "offline heuristic summary" in report.narrative
    assert "LLM agent loop failed" in report.narrative
    assert len(report.findings) == 1  # ...but findings are still grounded in the real scan
