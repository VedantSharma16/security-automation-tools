"""The agentic investigation loop.

:class:`SocAgent` drives a multi-step, tool-calling investigation of a
security incident. In "live" mode it uses the Claude Messages API's native
tool-use loop: the model decides which tools to call and in what order,
inspects each result, and eventually calls a special ``submit_final_report``
tool to conclude. Without an API key (or without the ``anthropic`` package
installed), it falls back to a deterministic offline planner that calls the
exact same tool functions in a fixed, sensible order and derives the verdict
with rule-based scoring — so the agent's tool protocol is fully testable and
runnable with zero network access or API cost.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from soc_agent import tools
from soc_agent.schemas import ALL_TOOLS

DEFAULT_MODEL = "claude-sonnet-5"
DEFAULT_MAX_TURNS = 8

SYSTEM_PROMPT = (
    "You are an autonomous SOC (Security Operations Center) analyst agent. "
    "You will be given a raw security incident (alert text, log excerpts, "
    "and/or a list of running processes). Investigate it thoroughly using "
    "the tools available to you before drawing conclusions:\n"
    "1. Extract indicators of compromise from the incident text.\n"
    "2. Check any extracted indicators against threat intelligence.\n"
    "3. Analyze any log content for brute-force, compromise, or privilege "
    "escalation patterns.\n"
    "4. Check any provided process list for suspicious activity.\n"
    "5. Look up the MITRE ATT&CK techniques relevant to what you found.\n"
    "Only after gathering sufficient evidence, call submit_final_report to "
    "conclude the investigation with a severity rating, a concise summary, "
    "the supporting technique ids, and concrete recommended actions. Do not "
    "call submit_final_report as your first action."
)


@dataclass
class ToolCallRecord:
    tool: str
    input: dict
    output: Any

    def to_dict(self) -> dict:
        return {"tool": self.tool, "input": self.input, "output": self.output}


@dataclass
class AgentReport:
    severity: str
    summary: str
    technique_ids: list[str]
    techniques: list[dict]
    iocs: dict
    recommended_actions: list[str]
    trace: list[ToolCallRecord] = field(default_factory=list)
    llm_backed: bool = False
    notes: str | None = None

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "summary": self.summary,
            "technique_ids": self.technique_ids,
            "techniques": self.techniques,
            "iocs": self.iocs,
            "recommended_actions": self.recommended_actions,
            "trace": [record.to_dict() for record in self.trace],
            "llm_backed": self.llm_backed,
            "notes": self.notes,
        }


def _score_severity(intel_hits: list[dict], log_findings: list[dict], process_hits: list[dict]) -> str:
    has_known_malicious = bool(intel_hits)
    has_compromise = any(f["type"] == "likely_compromise" for f in log_findings)
    has_privesc = any(f["type"] == "privilege_escalation" for f in log_findings)
    has_brute_force = any(f["type"] == "brute_force" for f in log_findings)
    has_process_hit = bool(process_hits)

    if has_known_malicious and (has_compromise or has_privesc or has_process_hit):
        return "critical"
    if has_compromise and has_process_hit:
        return "critical"
    if has_known_malicious or has_compromise or has_process_hit or has_privesc:
        return "high"
    if has_brute_force:
        return "medium"
    return "low"


def _build_summary(
    severity: str,
    intel_hits: list[dict],
    log_findings: list[dict],
    process_hits: list[dict],
) -> str:
    parts = [f"Severity assessed as {severity.upper()}."]

    if intel_hits:
        named = ", ".join(f"{hit['indicator']} ({hit['category']})" for hit in intel_hits)
        parts.append(f"Known-malicious indicators observed: {named}.")

    by_type: dict[str, list[dict]] = {}
    for finding in log_findings:
        by_type.setdefault(finding["type"], []).append(finding)

    if "brute_force" in by_type:
        ips = ", ".join(f["source_ip"] for f in by_type["brute_force"])
        parts.append(f"Brute-force login activity detected from: {ips}.")
    if "likely_compromise" in by_type:
        ips = ", ".join(f["source_ip"] for f in by_type["likely_compromise"])
        parts.append(f"A successful login followed failed attempts from: {ips}, suggesting compromise.")
    if "privilege_escalation" in by_type:
        parts.append("Privilege escalation activity (sudo) was observed after the login.")

    if process_hits:
        procs = ", ".join(hit["process"] for hit in process_hits)
        parts.append(f"Suspicious process activity detected: {procs}.")

    if len(parts) == 1:
        parts.append("No indicators, log correlation, or process activity crossed a suspicious threshold.")

    return " ".join(parts)


def _build_recommended_actions(
    severity: str, intel_hits: list[dict], log_findings: list[dict], process_hits: list[dict]
) -> list[str]:
    if severity == "low":
        return ["No action required; continue routine monitoring."]

    actions = []
    compromised_ips = {f["source_ip"] for f in log_findings if f["type"] == "likely_compromise"}
    if compromised_ips or process_hits:
        actions.append("Isolate the affected host(s) from the network pending further analysis.")
    if compromised_ips:
        actions.append("Force a password reset / revoke sessions for the affected account(s).")
    if intel_hits:
        actions.append("Block the known-malicious indicators at the firewall/EDR and hunt for related activity.")
    if process_hits:
        actions.append("Collect a forensic memory/process snapshot before killing the suspicious process(es).")
    if any(f["type"] == "brute_force" for f in log_findings) and not compromised_ips:
        actions.append("Rate-limit or block the source IP(s) of the brute-force attempts.")
    if not actions:
        actions.append("Escalate to a tier-2 analyst for manual review of the flagged evidence.")
    return actions


def _resolve_techniques(technique_ids: list[str]) -> list[dict]:
    return [tools.lookup_mitre_technique(tid) for tid in technique_ids]


class SocAgent:
    """Drives an investigation, either via live tool-use LLM calls or an
    offline deterministic planner that exercises the same tool functions."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        max_turns: int = DEFAULT_MAX_TURNS,
    ):
        self.model = model
        self.max_turns = max_turns
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

    def investigate(self, incident_text: str, processes: list[str] | None = None) -> AgentReport:
        if self._client is not None:
            try:
                return self._investigate_live(incident_text, processes)
            except Exception as exc:  # pragma: no cover - network/SDK failure path
                report = self._investigate_offline(incident_text, processes)
                report.notes = f"Live LLM investigation failed, offline planner used instead: {exc}"
                return report
        return self._investigate_offline(incident_text, processes)

    # -- live, LLM-driven tool-use loop -------------------------------------

    def _execute_tool(self, name: str, tool_input: dict, trace: list[ToolCallRecord]) -> Any:
        func = tools.TOOL_REGISTRY.get(name)
        if func is None:
            result = {"error": f"Unknown tool: {name}"}
        else:
            try:
                result = func(**tool_input)
            except Exception as exc:  # keep the loop alive on a bad tool call
                result = {"error": str(exc)}
        trace.append(ToolCallRecord(tool=name, input=tool_input, output=result))
        return result

    def _investigate_live(self, incident_text: str, processes: list[str] | None) -> AgentReport:
        user_content = f"## Incident\n{incident_text.strip()}"
        if processes:
            user_content += "\n\n## Observed running processes\n" + "\n".join(f"- {p}" for p in processes)

        messages: list[dict] = [{"role": "user", "content": user_content}]
        trace: list[ToolCallRecord] = []

        for _ in range(self.max_turns):
            response = self._client.messages.create(
                model=self.model,
                max_tokens=1500,
                system=SYSTEM_PROMPT,
                tools=ALL_TOOLS,
                messages=messages,
            )
            messages.append({"role": "assistant", "content": response.content})

            tool_uses = [block for block in response.content if getattr(block, "type", "") == "tool_use"]
            if not tool_uses:
                break

            final_block = next((b for b in tool_uses if b.name == "submit_final_report"), None)
            if final_block is not None:
                verdict = final_block.input
                return AgentReport(
                    severity=verdict["severity"],
                    summary=verdict["summary"],
                    technique_ids=list(verdict.get("technique_ids", [])),
                    techniques=_resolve_techniques(list(verdict.get("technique_ids", []))),
                    iocs=self._iocs_from_trace(trace),
                    recommended_actions=list(verdict.get("recommended_actions", [])),
                    trace=trace,
                    llm_backed=True,
                )

            tool_results = []
            for block in tool_uses:
                result = self._execute_tool(block.name, block.input, trace)
                tool_results.append(
                    {"type": "tool_result", "tool_use_id": block.id, "content": json.dumps(result)}
                )
            messages.append({"role": "user", "content": tool_results})

        # Model gathered evidence but never called submit_final_report within
        # max_turns — fall back to the same rule-based synthesis the offline
        # planner uses, over whatever the model actually looked up.
        report = self._synthesize_from_trace(trace)
        report.llm_backed = True
        report.notes = f"Model did not conclude within {self.max_turns} turns; verdict synthesized from its tool calls."
        return report

    @staticmethod
    def _iocs_from_trace(trace: list[ToolCallRecord]) -> dict:
        for record in trace:
            if record.tool == "extract_iocs":
                return record.output
        return {"ips": [], "domains": [], "hashes": []}

    @staticmethod
    def _synthesize_from_trace(trace: list[ToolCallRecord]) -> AgentReport:
        intel_hits = [
            r.output
            for r in trace
            if r.tool == "check_threat_intel" and isinstance(r.output, dict) and r.output.get("is_known_malicious")
        ]
        log_findings: list[dict] = []
        for r in trace:
            if r.tool == "analyze_auth_log" and isinstance(r.output, dict):
                log_findings.extend(r.output.get("findings", []))
        process_hits: list[dict] = []
        for r in trace:
            if r.tool == "check_process_list" and isinstance(r.output, dict):
                process_hits.extend(r.output.get("suspicious", []))

        severity = _score_severity(intel_hits, log_findings, process_hits)
        technique_ids = sorted(
            {f["technique_id"] for f in log_findings} | {h["technique_id"] for h in process_hits}
        )
        return AgentReport(
            severity=severity,
            summary=_build_summary(severity, intel_hits, log_findings, process_hits),
            technique_ids=technique_ids,
            techniques=_resolve_techniques(technique_ids),
            iocs=SocAgent._iocs_from_trace(trace),
            recommended_actions=_build_recommended_actions(severity, intel_hits, log_findings, process_hits),
            trace=trace,
            llm_backed=False,
        )

    # -- offline, deterministic planner --------------------------------------

    def _investigate_offline(self, incident_text: str, processes: list[str] | None) -> AgentReport:
        trace: list[ToolCallRecord] = []

        iocs = tools.extract_iocs(incident_text)
        trace.append(ToolCallRecord("extract_iocs", {"text": incident_text}, iocs))

        intel_hits = []
        for category, values in (("ip", iocs["ips"]), ("domain", iocs["domains"]), ("hash", iocs["hashes"])):
            for value in values:
                result = tools.check_threat_intel(value, category)
                trace.append(
                    ToolCallRecord("check_threat_intel", {"indicator": value, "category": category}, result)
                )
                if result["is_known_malicious"]:
                    intel_hits.append(result)

        log_result = tools.analyze_auth_log(incident_text)
        trace.append(ToolCallRecord("analyze_auth_log", {"log_text": incident_text}, log_result))
        log_findings = log_result["findings"]

        process_hits: list[dict] = []
        if processes:
            process_result = tools.check_process_list(processes)
            trace.append(ToolCallRecord("check_process_list", {"processes": processes}, process_result))
            process_hits = process_result["suspicious"]

        technique_ids = sorted(
            {f["technique_id"] for f in log_findings} | {h["technique_id"] for h in process_hits}
        )
        for tid in technique_ids:
            technique = tools.lookup_mitre_technique(tid)
            trace.append(ToolCallRecord("lookup_mitre_technique", {"technique_id": tid}, technique))

        severity = _score_severity(intel_hits, log_findings, process_hits)

        return AgentReport(
            severity=severity,
            summary=_build_summary(severity, intel_hits, log_findings, process_hits),
            technique_ids=technique_ids,
            techniques=_resolve_techniques(technique_ids),
            iocs=iocs,
            recommended_actions=_build_recommended_actions(severity, intel_hits, log_findings, process_hits),
            trace=trace,
            llm_backed=False,
        )
