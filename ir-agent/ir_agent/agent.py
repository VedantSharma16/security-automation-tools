"""The agentic investigation loop.

Two modes, selected automatically:

- **Live** (``ANTHROPIC_API_KEY`` set and ``anthropic`` installed): the LLM
  drives a ReAct-style tool-use loop. It decides which of the four
  investigation tools to call and in what order, reads each tool's result,
  and must finish by calling the ``submit_incident_report`` tool with a
  structured verdict — there is no free-text final answer to parse.
- **Offline** (no key / SDK): a fixed, deterministic pipeline calls every
  applicable tool in a sensible order and synthesizes the same structured
  report shape via plain heuristics. This keeps the agent fully runnable and
  testable without any API access, and doubles as a sanity baseline for what
  the live agent's tool choices should look like.

Both modes return the same ``AgentResult`` shape, so ``report.py`` and the
CLI don't need to know which mode produced it.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from .tools import enrichment, ioc_extraction, log_analysis, mitre_mapping
from .schemas import ALL_TOOLS

DEFAULT_MODEL = "claude-sonnet-5"
DEFAULT_MAX_TOOL_TURNS = 8

SYSTEM_PROMPT = (
    "You are an incident-response agent investigating a raw security alert or "
    "log excerpt. You have four tools available to gather evidence: "
    "extract_iocs, enrich_indicators, analyze_auth_log, and "
    "map_attack_techniques. Call whichever of them are relevant, in whatever "
    "order makes sense — you do not need to call every tool (for example, "
    "skip analyze_auth_log if the text has no log lines). Reason from actual "
    "tool output, not assumptions. When you have enough evidence, call "
    "submit_incident_report exactly once with your final severity rating, "
    "a plain-language summary, the specific indicators that matter, the "
    "MITRE ATT&CK technique IDs implicated, and concrete recommended actions "
    "for the on-call analyst. Do not submit a report before calling at least "
    "one investigation tool."
)


@dataclass
class ToolCall:
    tool: str
    input: dict
    output: dict


@dataclass
class AgentResult:
    mode: str  # "live", "live-fallback", or "offline"
    severity: str
    summary: str
    key_indicators: list[str]
    attack_techniques: list[str]
    recommended_actions: list[str]
    transcript: list[ToolCall] = field(default_factory=list)
    raw_findings: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "severity": self.severity,
            "summary": self.summary,
            "key_indicators": self.key_indicators,
            "attack_techniques": self.attack_techniques,
            "recommended_actions": self.recommended_actions,
            "transcript": [
                {"tool": call.tool, "input": call.input, "output": call.output}
                for call in self.transcript
            ],
        }


def dispatch_tool(name: str, tool_input: dict) -> dict:
    """Execute one investigation tool by name. Raises ValueError for unknown tools."""
    if name == "extract_iocs":
        return ioc_extraction.extract_iocs(tool_input["text"])
    if name == "enrich_indicators":
        return {"enrichment": enrichment.enrich_indicators(tool_input["indicators"])}
    if name == "analyze_auth_log":
        return log_analysis.analyze_auth_log(tool_input["text"])
    if name == "map_attack_techniques":
        return {
            "techniques": mitre_mapping.map_attack_techniques(
                tool_input["text"], tool_input.get("top_k", 3)
            )
        }
    raise ValueError(f"Unknown tool: {name}")


def _get(block, key):
    if isinstance(block, dict):
        return block.get(key)
    return getattr(block, key, None)


def _content_block_to_dict(block) -> dict:
    block_type = _get(block, "type")
    if block_type == "text":
        return {"type": "text", "text": _get(block, "text")}
    if block_type == "tool_use":
        return {
            "type": "tool_use",
            "id": _get(block, "id"),
            "name": _get(block, "name"),
            "input": _get(block, "input"),
        }
    raise ValueError(f"Unsupported content block type: {block_type!r}")


class IncidentResponseAgent:
    """Investigates incident text and produces a structured AgentResult."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        max_tool_turns: int = DEFAULT_MAX_TOOL_TURNS,
    ):
        self.model = model
        self.max_tool_turns = max_tool_turns
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

    def investigate(self, incident_text: str) -> AgentResult:
        if self._client is not None:
            try:
                return self._investigate_live(incident_text)
            except Exception:  # pragma: no cover - network/SDK failure path
                return self._investigate_offline(incident_text, mode="live-fallback")
        return self._investigate_offline(incident_text)

    # -- live, LLM-driven tool-use loop -----------------------------------

    def _investigate_live(self, incident_text: str) -> AgentResult:
        messages = [{"role": "user", "content": incident_text}]
        transcript: list[ToolCall] = []
        final_report = None

        for turn in range(self.max_tool_turns):
            is_last_turn = turn == self.max_tool_turns - 1
            kwargs = dict(
                model=self.model,
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                tools=ALL_TOOLS,
                messages=messages,
            )
            if is_last_turn:
                kwargs["tool_choice"] = {"type": "tool", "name": "submit_incident_report"}

            response = self._client.messages.create(**kwargs)
            content_blocks = [_content_block_to_dict(b) for b in response.content]
            messages.append({"role": "assistant", "content": content_blocks})

            tool_use_blocks = [b for b in content_blocks if b["type"] == "tool_use"]
            if not tool_use_blocks:
                break

            tool_result_blocks = []
            done = False
            for block in tool_use_blocks:
                if block["name"] == "submit_incident_report":
                    final_report = block["input"]
                    done = True
                    continue
                output = dispatch_tool(block["name"], block["input"])
                transcript.append(ToolCall(tool=block["name"], input=block["input"], output=output))
                tool_result_blocks.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block["id"],
                        "content": json.dumps(output),
                    }
                )

            if done:
                break

            messages.append({"role": "user", "content": tool_result_blocks})

        if final_report is None:
            return self._investigate_offline(
                incident_text, transcript=transcript, mode="live-fallback"
            )

        return AgentResult(
            mode="live",
            severity=final_report["severity"],
            summary=final_report["summary"],
            key_indicators=list(final_report["key_indicators"]),
            attack_techniques=list(final_report["attack_techniques"]),
            recommended_actions=list(final_report["recommended_actions"]),
            transcript=transcript,
            raw_findings=_aggregate_findings(transcript),
        )

    # -- offline / fallback deterministic pipeline ------------------------

    def _investigate_offline(
        self,
        incident_text: str,
        transcript: list[ToolCall] | None = None,
        mode: str = "offline",
    ) -> AgentResult:
        transcript = list(transcript) if transcript else []

        indicators = ioc_extraction.extract_iocs(incident_text)
        transcript.append(ToolCall("extract_iocs", {"text": incident_text}, indicators))

        enrichment_results = enrichment.enrich_indicators(indicators)
        transcript.append(
            ToolCall(
                "enrich_indicators",
                {"indicators": indicators},
                {"enrichment": enrichment_results},
            )
        )

        log_findings = None
        if log_analysis.looks_like_auth_log(incident_text):
            log_findings = log_analysis.analyze_auth_log(incident_text)
            transcript.append(ToolCall("analyze_auth_log", {"text": incident_text}, log_findings))

        mapping_text = _build_mapping_text(incident_text, log_findings)
        techniques = mitre_mapping.map_attack_techniques(mapping_text)
        transcript.append(
            ToolCall("map_attack_techniques", {"text": mapping_text}, {"techniques": techniques})
        )

        hits = enrichment.known_malicious_hits(enrichment_results)
        severity = _score_severity(log_findings, hits)
        summary = _build_summary(indicators, hits, log_findings, techniques)
        key_indicators = [h["value"] for h in hits] or _fallback_indicators(indicators)
        attack_technique_ids = [t["id"] for t in techniques]
        recommended_actions = _build_recommendations(severity, hits, log_findings)

        return AgentResult(
            mode=mode,
            severity=severity,
            summary=summary,
            key_indicators=key_indicators,
            attack_techniques=attack_technique_ids,
            recommended_actions=recommended_actions,
            transcript=transcript,
            raw_findings={
                "indicators": indicators,
                "enrichment": enrichment_results,
                "log_findings": log_findings,
                "techniques": techniques,
            },
        )


def _aggregate_findings(transcript: list[ToolCall]) -> dict:
    findings: dict = {}
    for call in transcript:
        findings[call.tool] = call.output
    return findings


def _build_mapping_text(incident_text: str, log_findings: dict | None) -> str:
    parts = [incident_text]
    if log_findings:
        if log_findings["brute_force_ips"]:
            parts.append("brute force failed password repeated login attempts")
        if log_findings["likely_compromised_ips"]:
            parts.append("accepted password successful login valid credentials")
        if log_findings["privilege_escalation"]:
            parts.append("sudo privilege escalation elevated to root")
        for event in log_findings["persistence_events"]:
            if event["type"] == "useradd":
                parts.append("useradd new user created uid 0")
            else:
                parts.append("crontab cron job scheduled task")
    return " ".join(parts)


def _score_severity(log_findings: dict | None, hits: list[dict]) -> str:
    high_confidence_hits = [h for h in hits if h["confidence"] == "high"]
    compromised = bool(log_findings and log_findings["likely_compromised_ips"])
    persistence = bool(log_findings and log_findings["persistence_events"])
    brute_force = bool(log_findings and log_findings["brute_force_ips"])
    privilege_escalation = bool(log_findings and log_findings["privilege_escalation"])

    if high_confidence_hits and (compromised or persistence):
        return "critical"
    if high_confidence_hits or compromised or persistence or privilege_escalation:
        return "high"
    if hits or brute_force:
        return "medium"
    return "low"


def _fallback_indicators(indicators: dict) -> list[str]:
    values: list[str] = []
    for ip in indicators.get("ips", []):
        values.append(ip["value"])
    values.extend(indicators.get("domains", []))
    values.extend(h["value"] for h in indicators.get("hashes", []))
    values.extend(indicators.get("urls", []))
    return values[:5]


def _build_summary(
    indicators: dict,
    hits: list[dict],
    log_findings: dict | None,
    techniques: list[dict],
) -> str:
    total = ioc_extraction.total_indicator_count(indicators)
    sentences = [f"Extracted {total} indicator(s) from the supplied incident text."]

    if hits:
        named = ", ".join(f"{h['value']} ({h['category']})" for h in hits)
        sentences.append(f"Known-malicious indicators observed: {named}.")
    else:
        sentences.append("No indicators matched the local threat-intel feed.")

    if log_findings:
        if log_findings["brute_force_ips"]:
            sentences.append(
                "Brute-force login attempts detected from "
                f"{', '.join(log_findings['brute_force_ips'])}."
            )
        if log_findings["likely_compromised_ips"]:
            sentences.append(
                "A successful login followed brute-force attempts from "
                f"{', '.join(log_findings['likely_compromised_ips'])} — likely compromise."
            )
        if log_findings["persistence_events"]:
            sentences.append(
                f"{len(log_findings['persistence_events'])} persistence-related event(s) observed "
                "(new accounts and/or crontab edits)."
            )

    if techniques:
        top = techniques[0]
        sentences.append(
            f"Behavior most closely resembles ATT&CK technique {top['id']} ({top['name']})."
        )

    return " ".join(sentences)


def _build_recommendations(
    severity: str,
    hits: list[dict],
    log_findings: dict | None,
) -> list[str]:
    actions = []
    if severity in ("high", "critical"):
        actions.append("Isolate the affected host(s) from the network pending investigation.")
    if hits:
        actions.append(
            "Block the flagged indicators at the firewall/EDR and pivot on them across the SIEM "
            "for related activity."
        )
    if log_findings and log_findings["likely_compromised_ips"]:
        actions.append(
            "Force a password reset for any accounts logged in from "
            f"{', '.join(log_findings['likely_compromised_ips'])} and review their session history."
        )
    if log_findings and log_findings["persistence_events"]:
        actions.append(
            "Audit newly created accounts and crontab entries for unauthorized persistence."
        )
    if not actions:
        actions.append(
            "No high-confidence findings — monitor for recurrence and re-run triage if related "
            "alerts arrive."
        )
    return actions
