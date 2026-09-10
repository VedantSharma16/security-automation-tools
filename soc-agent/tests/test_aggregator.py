from soc_agent.aggregator import build_report, recommended_actions
from soc_agent.router import RouterDecision
from soc_agent.tools import ToolResult, skipped


def _ok(tool, severity, finding_count, raw=None):
    return ToolResult(
        tool=tool,
        status="ok",
        severity=severity,
        finding_count=finding_count,
        headline=f"{finding_count} finding(s)",
        raw=raw or {},
    )


def test_overall_severity_is_max_across_ok_tools():
    results = {
        "log_triage": _ok("log_triage", "medium", 1),
        "ioc_triage": _ok("ioc_triage", "critical", 2),
        "process_hunter": skipped("process_hunter", "not requested"),
    }
    decision = RouterDecision(run_log_triage=True, run_ioc_triage=True, reasoning=["test"])

    report = build_report(results, decision, evidence_source="incident.txt")

    assert report["overall_severity"] == "critical"
    assert report["total_findings"] == 3
    assert report["tools_run"] == ["log_triage", "ioc_triage"]
    assert report["tools_skipped"] == ["process_hunter"]
    assert report["tools_errored"] == []


def test_overall_severity_is_none_when_nothing_ran():
    results = {
        "log_triage": skipped("log_triage", "n/a"),
        "ioc_triage": skipped("ioc_triage", "n/a"),
        "process_hunter": skipped("process_hunter", "n/a"),
    }
    report = build_report(results, router_decision=None, evidence_source=None)

    assert report["overall_severity"] == "none"
    assert report["total_findings"] == 0
    assert report["router"] is None


def test_errored_tools_are_tracked_separately():
    results = {
        "log_triage": ToolResult(tool="log_triage", status="error", error="boom"),
        "ioc_triage": _ok("ioc_triage", "low", 0),
    }
    report = build_report(results, router_decision=None, evidence_source="x.txt")

    assert report["tools_errored"] == ["log_triage"]
    assert "log_triage" not in report["tools_run"]


def test_recommended_actions_names_malicious_indicators():
    raw = {
        "enrichment": [
            {"value": "1.2.3.4", "is_known_malicious": True, "confidence": "high"},
            {"value": "example.com", "is_known_malicious": False, "confidence": "low"},
        ]
    }
    results = {"ioc_triage": _ok("ioc_triage", "high", 2, raw=raw)}
    report = build_report(results, router_decision=None, evidence_source="x.txt")

    actions = recommended_actions(report)
    assert any("1.2.3.4" in a for a in actions)
    assert not any("example.com" in a for a in actions)


def test_recommended_actions_flags_incomplete_coverage_on_errors():
    results = {"process_hunter": ToolResult(tool="process_hunter", status="error", error="no psutil")}
    report = build_report(results, router_decision=None, evidence_source=None)

    actions = recommended_actions(report)
    assert any("process_hunter" in a for a in actions)


def test_recommended_actions_default_when_nothing_found():
    report = build_report({}, router_decision=None, evidence_source=None)
    actions = recommended_actions(report)
    assert actions == ["No actionable findings from the tools that ran; continue routine monitoring."]
