from recon_agent import executor, planner
from recon_agent.models import Finding, ToolResult


def fake_registry(target=None):
    return {
        "dns_lookup": lambda: ToolResult(tool="dns", data={}, findings=[]),
        "http_headers": lambda: ToolResult(
            tool="http_headers",
            data={},
            findings=[
                Finding(
                    tool="http_headers",
                    severity="high",
                    title="Site not served over HTTPS",
                    detail="d",
                    recommendation="r",
                )
            ],
        ),
    }


def test_run_static_aggregates_findings_scores_and_grades(monkeypatch):
    monkeypatch.setattr(executor, "build_registry", fake_registry)

    report = executor.run("example.com")

    assert report.target == "example.com"
    assert len(report.findings) == 1
    assert report.score == 100 - 15
    assert report.grade == "B"
    assert "example.com" in report.narrative


def test_run_agentic_falls_back_to_static_plan_when_agent_returns_nothing(monkeypatch):
    monkeypatch.setattr(executor, "build_registry", fake_registry)
    monkeypatch.setattr(planner, "run_agentic", lambda registry, target, client=None: ([], ""))

    report = executor.run("example.com", agentic=True)

    assert len(report.findings) == 1
    assert report.score == 85


def test_run_agentic_keeps_the_agents_own_narrative(monkeypatch):
    monkeypatch.setattr(executor, "build_registry", fake_registry)

    def fake_run_agentic(registry, target, client=None):
        return [registry["dns_lookup"]()], "Agent-written summary."

    monkeypatch.setattr(planner, "run_agentic", fake_run_agentic)

    report = executor.run("example.com", agentic=True)

    assert report.narrative == "Agent-written summary."
    assert report.findings == []
    assert report.score == 100
