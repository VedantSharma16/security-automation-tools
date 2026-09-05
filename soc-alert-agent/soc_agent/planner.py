"""Deterministic, offline triage planner.

This is the agent's default backend and the one the test suite runs
against: a fixed sequence of tool calls (reputation lookup for every
observed indicator, asset criticality, alert correlation, then ATT&CK
technique retrieval), followed by a transparent point-based heuristic that
maps the gathered evidence to a verdict.

It exists for two reasons: the tool loop and reporting layers need to work
without any API key or network access (mirrors the offline-fallback
pattern used throughout this repo), and it gives an auditable, reproducible
baseline to compare the LLM-driven agent's tool choices and verdicts
against.
"""

from __future__ import annotations

from .models import Alert, AgentResult, AgentStep
from .tools import ToolRegistry

ESCALATE_THRESHOLD = 50
MONITOR_THRESHOLD = 20

_CONFIDENCE_POINTS = {"high": 50, "medium": 20, "low": 5, "unknown": 0}
_CRITICALITY_POINTS = {"crown_jewel": 20, "high": 10, "standard": 5, "low": 0, "unknown": 0}
_RELATED_ALERTS_POINTS = 15
_TECHNIQUE_STRONG_MATCH_POINTS = 15
_TECHNIQUE_WEAK_MATCH_POINTS = 8


def _indicators_to_check(alert: Alert) -> list[str]:
    values: list[str] = []
    if alert.src_ip:
        values.append(alert.src_ip)
    for category_values in alert.raw_indicators.values():
        values.extend(v for v in category_values if v not in values)
    return values


def run_deterministic(alert: Alert, tools: ToolRegistry, max_steps: int = 10) -> AgentResult:
    steps: list[AgentStep] = []
    score = 0
    step_no = 0

    def record(thought: str, tool_name: str, tool_args: dict) -> dict:
        nonlocal step_no
        step_no += 1
        result = tools.dispatch(tool_name, tool_args)
        steps.append(AgentStep(step_no, tool_name, tool_args, result, thought=thought))
        return result

    evidence: list[str] = []

    malicious_hits = []
    for indicator in _indicators_to_check(alert):
        rep = record(
            f"Check reputation of observed indicator '{indicator}'.",
            "lookup_ioc_reputation",
            {"indicator": indicator},
        )
        if rep["known_malicious"]:
            points = _CONFIDENCE_POINTS.get(rep["confidence"], 0)
            score += points
            malicious_hits.append(rep)
            evidence.append(
                f"indicator {rep['indicator']} is known malicious ({rep['confidence']} confidence: {rep['notes']})"
            )
        if step_no >= max_steps:
            break

    asset = record(
        f"Check business criticality of affected host '{alert.host}'.",
        "get_asset_criticality",
        {"host": alert.host},
    )
    score += _CRITICALITY_POINTS.get(asset["criticality"], 0)
    if asset["criticality"] in ("crown_jewel", "high"):
        evidence.append(f"affected host {alert.host} is a {asset['criticality']} asset ({asset['notes']})")

    related = record(
        "Check whether other queued alerts share this alert's source IP, host, or user "
        "(possible campaign correlation).",
        "check_related_alerts",
        {"alert_id": alert.alert_id},
    )
    if related["count"] > 0:
        score += _RELATED_ALERTS_POINTS
        evidence.append(f"{related['count']} related alert(s) in the queue share indicators with this one")

    technique = record(
        "Search MITRE ATT&CK techniques matching the alert description for context.",
        "search_attack_technique",
        {"query": alert.description, "top_k": 3},
    )
    top_matches = technique["matches"]
    if top_matches:
        best = top_matches[0]
        if best["score"] >= 2:
            score += _TECHNIQUE_STRONG_MATCH_POINTS
            evidence.append(f"description strongly matches ATT&CK {best['id']} ({best['name']})")
        else:
            score += _TECHNIQUE_WEAK_MATCH_POINTS
            evidence.append(f"description weakly matches ATT&CK {best['id']} ({best['name']})")

    if score >= ESCALATE_THRESHOLD:
        verdict = "escalate"
    elif score >= MONITOR_THRESHOLD:
        verdict = "monitor"
    else:
        verdict = "close"

    if evidence:
        reason = f"Risk score {score}/100 ({verdict}). " + "; ".join(evidence) + "."
    else:
        reason = f"Risk score {score}/100 ({verdict}). No corroborating evidence found in reputation, asset, correlation, or ATT&CK checks."

    record(f"Finalize verdict based on accumulated risk score ({score}/100).", verdict, {"reason": reason})

    return AgentResult(alert_id=alert.alert_id, verdict=verdict, reason=reason, steps=steps, backend="deterministic")
