"""The agent: an autonomous tool-calling investigation loop, with an offline fallback.

Live mode hands Claude the tool schemas from :mod:`soc_agent.tools` plus a
``submit_verdict`` tool, and lets the model decide *which* tools to call,
*in what order*, based on which fields are actually present on the alert —
that data-dependent branching is what makes this "agentic" rather than a
fixed pipeline. The loop terminates when the model calls ``submit_verdict``
or after :data:`MAX_TOOL_CALLS` rounds.

Offline mode (no ``ANTHROPIC_API_KEY``) runs a deterministic rule-based
planner that calls the *exact same* tool functions and applies a fixed
scoring heuristic. It exists so the full pipeline — investigation trace,
scoring, and recommended actions — is testable and runnable with zero
network access or API key, matching every other tool in this repo.
"""

from __future__ import annotations

import json
import os

from . import tools
from .playbook import AlertCase, IncidentReport, ToolCallRecord

DEFAULT_MODEL = "claude-sonnet-5"
MAX_TOOL_CALLS = 8

SYSTEM_PROMPT = (
    "You are an autonomous SOC tier-1 triage agent. You will be given a security "
    "alert. Investigate it by calling the available lookup tools as needed — only "
    "call a tool when the alert has a field it's relevant to (e.g. don't look up a "
    "username that isn't present). You do not need to call every tool. Once you "
    "have gathered enough evidence, call `submit_verdict` exactly once with your "
    "final verdict, confidence, the evidence that supports it, and concrete "
    "recommended containment actions. Do not call submit_verdict before making at "
    "least one investigative tool call when the alert has fields to investigate."
)

SUBMIT_VERDICT_TOOL = {
    "name": "submit_verdict",
    "description": "Submit the final triage verdict for this alert. Call this exactly once, "
    "after gathering evidence with the investigative tools.",
    "input_schema": {
        "type": "object",
        "properties": {
            "verdict": {"type": "string", "enum": ["benign", "suspicious", "malicious"]},
            "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
            "score": {"type": "integer", "description": "A 0-100 risk score."},
            "evidence": {"type": "array", "items": {"type": "string"}},
            "recommended_actions": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["verdict", "confidence", "evidence", "recommended_actions"],
    },
}


def _format_alert_for_model(alert: AlertCase) -> str:
    fields = {
        "alert_id": alert.alert_id,
        "description": alert.description,
        "timestamp": alert.timestamp,
        "hostname": alert.hostname,
        "source_ip": alert.source_ip,
        "dest_ip": alert.dest_ip,
        "username": alert.username,
        "process_name": alert.process_name,
    }
    present = {k: v for k, v in fields.items() if v}
    return "Investigate the following alert:\n\n" + json.dumps(present, indent=2)


class SecOpsAgent:
    """Wraps the Claude tool-use loop with a safe, fully offline fallback."""

    def __init__(self, api_key: str | None = None, model: str = DEFAULT_MODEL):
        self.model = model
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._client = None
        if self.api_key:
            try:
                import anthropic  # type: ignore

                self._client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                self._client = None

    @property
    def is_live(self) -> bool:
        return self._client is not None

    def investigate(self, alert: AlertCase) -> IncidentReport:
        if self._client is not None:
            try:
                return self._investigate_live(alert)
            except Exception as exc:  # pragma: no cover - network/SDK failure path
                report = self._investigate_offline(alert)
                report.warnings.append(f"Live agent call failed, offline planner used: {exc}")
                return report
        return self._investigate_offline(alert)

    # -- offline deterministic planner -----------------------------------

    def _investigate_offline(self, alert: AlertCase) -> IncidentReport:
        trace: list[ToolCallRecord] = []
        evidence: list[str] = []
        score = 0

        asset = None
        if alert.hostname:
            asset = tools.lookup_asset_criticality(alert.hostname)
            trace.append(ToolCallRecord("lookup_asset_criticality", {"hostname": alert.hostname}, asset))
            if asset["criticality"] == "crown_jewel":
                score += 25
                evidence.append(f"{alert.hostname} is a crown-jewel asset (owner: {asset.get('owner')}).")

        ioc_hits = []
        for field_name, indicator in (("source_ip", alert.source_ip), ("dest_ip", alert.dest_ip)):
            if not indicator:
                continue
            result = tools.lookup_ioc_reputation(indicator)
            trace.append(ToolCallRecord("lookup_ioc_reputation", {"indicator": indicator}, result))
            if result["verdict"] == "malicious":
                score += 40
                evidence.append(f"{field_name} {indicator} is a KNOWN MALICIOUS indicator ({result.get('notes')}).")
                ioc_hits.append(result)
            elif result["verdict"] == "suspicious":
                score += 15
                evidence.append(f"{field_name} {indicator} is flagged suspicious ({result.get('notes')}).")
                ioc_hits.append(result)

        user_risk = None
        if alert.username:
            user_risk = tools.lookup_user_risk(alert.username)
            trace.append(ToolCallRecord("lookup_user_risk", {"username": alert.username}, user_risk))
            if user_risk["anomalous"]:
                score += 20
                evidence.append(
                    f"User {alert.username} flagged anomalous "
                    f"({user_risk['failed_logins_24h']} failed logins/24h, privilege={user_risk['privilege']})."
                )

        process_check = None
        if alert.hostname and alert.process_name:
            process_check = tools.check_process_baseline(alert.hostname, alert.process_name)
            trace.append(
                ToolCallRecord(
                    "check_process_baseline",
                    {"hostname": alert.hostname, "process_name": alert.process_name},
                    process_check,
                )
            )
            if process_check["host_has_baseline"] and process_check["is_baselined"] is False:
                score += 20
                evidence.append(
                    f"Process '{alert.process_name}' on {alert.hostname} is NOT in the known-good baseline."
                )

        verdict, confidence = self._score_to_verdict(score)
        actions = self._recommend_actions(verdict, asset, ioc_hits, user_risk, process_check)

        if not evidence:
            evidence.append("No relevant fields present, or all lookups returned clean/unknown results.")

        return IncidentReport(
            alert=alert,
            trace=trace,
            verdict=verdict,
            confidence=confidence,
            score=score,
            evidence=evidence,
            recommended_actions=actions,
            mode="offline",
        )

    @staticmethod
    def _score_to_verdict(score: int) -> tuple[str, str]:
        if score >= 60:
            return "malicious", "high"
        if score >= 30:
            return "suspicious", "medium"
        return "benign", "low"

    @staticmethod
    def _recommend_actions(verdict, asset, ioc_hits, user_risk, process_check) -> list[str]:
        actions: list[str] = []
        if verdict == "malicious":
            actions.append("Isolate the affected host from the network pending investigation.")
            if ioc_hits:
                actions.append("Block the flagged indicator(s) at the firewall/proxy layer.")
            if user_risk and user_risk.get("anomalous"):
                actions.append("Disable or force a credential reset for the associated user account.")
            if process_check and process_check.get("is_baselined") is False:
                actions.append("Kill the unbaselined process and collect a forensic memory/disk image.")
        elif verdict == "suspicious":
            actions.append("Escalate to a tier-2 analyst for manual review within the shift SLA.")
            actions.append("Continue monitoring the host/user for follow-on activity.")
            if asset and asset.get("criticality") == "crown_jewel":
                actions.append("Notify the asset owner given the crown-jewel criticality of the host.")
        else:
            actions.append("No action required; close the alert as benign.")
        return actions

    # -- live Claude tool-use loop -----------------------------------------

    def _investigate_live(self, alert: AlertCase) -> IncidentReport:
        trace: list[ToolCallRecord] = []
        messages = [{"role": "user", "content": _format_alert_for_model(alert)}]
        tool_defs = tools.TOOL_SCHEMAS + [SUBMIT_VERDICT_TOOL]

        for _ in range(MAX_TOOL_CALLS):
            response = self._client.messages.create(
                model=self.model,
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                tools=tool_defs,
                messages=messages,
            )
            messages.append({"role": "assistant", "content": response.content})

            tool_uses = [b for b in response.content if getattr(b, "type", "") == "tool_use"]
            if not tool_uses:
                break

            tool_results = []
            submitted = None
            for block in tool_uses:
                if block.name == "submit_verdict":
                    submitted = block.input
                    tool_results.append(
                        {"type": "tool_result", "tool_use_id": block.id, "content": "Verdict recorded."}
                    )
                    continue
                impl = tools.TOOL_IMPLEMENTATIONS.get(block.name)
                result = impl(block.input) if impl else {"error": f"unknown tool {block.name}"}
                trace.append(ToolCallRecord(block.name, block.input, result))
                tool_results.append(
                    {"type": "tool_result", "tool_use_id": block.id, "content": json.dumps(result)}
                )

            if submitted is not None:
                return IncidentReport(
                    alert=alert,
                    trace=trace,
                    verdict=submitted.get("verdict", "suspicious"),
                    confidence=submitted.get("confidence", "medium"),
                    score=submitted.get("score", 0),
                    evidence=submitted.get("evidence", []),
                    recommended_actions=submitted.get("recommended_actions", []),
                    mode="live",
                )

            messages.append({"role": "user", "content": tool_results})

        report = self._investigate_offline(alert)
        report.warnings.append(
            "Live agent exceeded the max tool-call budget without submitting a verdict; "
            "used the offline planner's result instead."
        )
        return report
