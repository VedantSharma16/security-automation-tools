"""Merge per-tool results into a single consolidated incident report."""

from __future__ import annotations

from datetime import datetime, timezone

from .router import RouterDecision
from .tools import ToolResult, severity_rank


def build_report(
    tool_results: dict[str, ToolResult],
    router_decision: RouterDecision | None,
    evidence_source: str | None,
) -> dict:
    """Combine ToolResults into one JSON-serializable incident report.

    ``tool_results`` maps tool name -> ToolResult for every tool that was run
    or skipped (skipped/errored tools are included so the report is honest
    about what it did *not* cover, not just what it found).
    """
    ok_results = [r for r in tool_results.values() if r.status == "ok"]

    overall_severity = "none"
    if ok_results:
        overall_severity = max((r.severity or "none" for r in ok_results), key=severity_rank)

    total_findings = sum(r.finding_count for r in ok_results)

    tools_run = [r.tool for r in tool_results.values() if r.status == "ok"]
    tools_skipped = [r.tool for r in tool_results.values() if r.status == "skipped"]
    tools_errored = [r.tool for r in tool_results.values() if r.status == "error"]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evidence_source": evidence_source,
        "router": router_decision.to_dict() if router_decision else None,
        "overall_severity": overall_severity,
        "total_findings": total_findings,
        "tools_run": tools_run,
        "tools_skipped": tools_skipped,
        "tools_errored": tools_errored,
        "tool_results": {name: result.to_dict() for name, result in tool_results.items()},
        "narrative": None,
    }


def recommended_actions(report: dict) -> list[str]:
    """Deterministic, evidence-grounded action list -- used by the template
    narrative and as a sanity backstop even when the LLM narrative is used."""
    actions: list[str] = []
    results = report["tool_results"]

    log_result = results.get("log_triage")
    if log_result and log_result["status"] == "ok" and log_result["finding_count"]:
        findings = log_result["raw"]["findings"]
        types = {f["type"] for f in findings}
        if "compromise_after_brute_force" in types:
            actions.append("Rotate credentials for the compromised account(s) immediately.")
        if "brute_force" in types:
            actions.append("Block or rate-limit the source IP(s) behind the brute-force attempts.")
        if "persistence_root_account" in types or "persistence_crontab" in types:
            actions.append("Audit and remove unauthorized accounts and crontab entries.")
        if "privilege_escalation" in types:
            actions.append("Review sudo usage around the incident window for unauthorized escalation.")

    ioc_result = results.get("ioc_triage")
    if ioc_result and ioc_result["status"] == "ok":
        malicious = [e for e in ioc_result["raw"]["enrichment"] if e["is_known_malicious"]]
        if malicious:
            actions.append(
                "Block/hunt on the known-malicious indicators: "
                + ", ".join(sorted({e["value"] for e in malicious}))
                + "."
            )

    proc_result = results.get("process_hunter")
    if proc_result and proc_result["status"] == "ok" and proc_result["finding_count"]:
        actions.append("Isolate the host and investigate the flagged processes before they are killed (preserve evidence).")

    if report["tools_errored"]:
        actions.append(
            "Re-run the errored tool(s) once fixed -- coverage is incomplete: "
            + ", ".join(report["tools_errored"])
            + "."
        )

    if not actions:
        actions.append("No actionable findings from the tools that ran; continue routine monitoring.")

    return actions
