"""All Claude API access for the agent, with safe offline fallbacks.

Two capabilities live here, both optional and both falling back to
deterministic behavior when ``ANTHROPIC_API_KEY`` isn't set or the call
fails:

- :meth:`LLMClient.plan_next` — a single real Claude *tool-use* call that
  picks the next investigative step (used by :class:`soc_agent.planner.LLMPlanner`).
- :meth:`LLMClient.narrate` — a plain-text call that writes the analyst-facing
  narrative from the finished investigation transcript.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from soc_agent.models import Incident, ToolStep

DEFAULT_MODEL = "claude-sonnet-5"

NARRATIVE_SYSTEM_PROMPT = (
    "You are a SOC tier-2 analyst assistant. Given an incident and the results "
    "of an automated investigation (tool calls and their findings), write a "
    "concise incident narrative: what happened, why it matters, and confirm "
    "or refine the recommended actions. Ground every claim strictly in the "
    "provided findings — never invent evidence that wasn't gathered."
)

PLANNER_SYSTEM_PROMPT = (
    "You are the planning step of an autonomous SOC investigation agent. "
    "Given the incident and the tool calls made so far, choose exactly one "
    "next action: call the single most useful tool to gather more evidence, "
    "or call finish_investigation once you have enough evidence to reach a "
    "verdict. Do not repeat a tool call with arguments already used. Prefer "
    "finishing early once the mandatory checks are clean and nothing "
    "suspicious has been found."
)


def _describe_state(state) -> str:
    incident = state.incident
    lines = [
        f"Incident {incident.incident_id}: {incident.description or '(no description)'}",
        f"Host: {incident.hostname}, User: {incident.user}",
        f"Process: {incident.process_name}, Command line: {incident.command_line}",
        f"Indicators: {', '.join(incident.indicators) or '(none)'}",
        "",
        "Tool calls so far:",
    ]
    if state.steps:
        for step in state.steps:
            lines.append(f"- {step.call.tool}({step.call.arguments}) -> {step.result}")
    else:
        lines.append("- (none yet)")
    return "\n".join(lines)


def _build_narrative_prompt(incident: Incident, steps: list[ToolStep], severity: str, actions: list[str]) -> str:
    lines = [
        "## Incident",
        f"ID: {incident.incident_id}",
        f"Host: {incident.hostname} | User: {incident.user}",
        f"Process: {incident.process_name} | Command line: {incident.command_line}",
        f"Description: {incident.description or '(none provided)'}",
        "",
        "## Investigation transcript",
    ]
    if steps:
        for step in steps:
            lines.append(f"- {step.call.tool}({step.call.arguments}) -> {step.result}")
    else:
        lines.append("- No tool calls were made.")
    lines += [
        "",
        f"## Heuristic severity: {severity}",
        "## Recommended actions",
    ]
    lines += [f"- {action}" for action in actions]
    return "\n".join(lines)


class LLMClient:
    """Wraps Anthropic API access; every method has a deterministic fallback."""

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

    # --- planning --------------------------------------------------------

    def plan_next(self, state, tool_specs) -> dict | None:
        """Ask Claude which tool to call next. Returns None to signal 'use the
        deterministic fallback' — either because no API key/SDK is available
        or because the call itself failed.
        """
        if self._client is None:
            return None

        tools_payload = [
            {"name": spec.name, "description": spec.description, "input_schema": spec.parameters}
            for spec in tool_specs
        ]
        tools_payload.append(
            {
                "name": "finish_investigation",
                "description": "Call once enough evidence has been gathered to reach a verdict.",
                "input_schema": {"type": "object", "properties": {}},
            }
        )

        try:
            response = self._client.messages.create(
                model=self.model,
                max_tokens=300,
                system=PLANNER_SYSTEM_PROMPT,
                tools=tools_payload,
                tool_choice={"type": "any"},
                messages=[{"role": "user", "content": _describe_state(state)}],
            )
        except Exception:  # pragma: no cover - network/SDK failure path
            return None

        for block in response.content:
            if getattr(block, "type", "") == "tool_use":
                return {"tool": block.name, "arguments": dict(block.input or {})}
        return None

    # --- narration ---------------------------------------------------------

    def narrate(self, incident: Incident, steps: list[ToolStep], severity: str, actions: list[str]) -> str:
        prompt = _build_narrative_prompt(incident, steps, severity, actions)
        if self._client is not None:
            try:
                response = self._client.messages.create(
                    model=self.model,
                    max_tokens=500,
                    system=NARRATIVE_SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": prompt}],
                )
                return "".join(
                    block.text for block in response.content if getattr(block, "type", "") == "text"
                ).strip()
            except Exception as exc:  # pragma: no cover - network/SDK failure path
                return self._offline_narrative(incident, steps, severity, actions) + f"\n\n[LLM call failed, offline fallback used: {exc}]"
        return self._offline_narrative(incident, steps, severity, actions)

    @staticmethod
    def _offline_narrative(incident: Incident, steps: list[ToolStep], severity: str, actions: list[str]) -> str:
        parts = [
            "[offline heuristic narrative — set ANTHROPIC_API_KEY for LLM-generated analysis]",
            f"Incident {incident.incident_id} on host {incident.hostname or 'unknown'} "
            f"(user: {incident.user or 'unknown'}) scored severity {severity.upper()}.",
        ]

        malicious = [s.result for s in steps if s.call.tool == "threat_intel_lookup" and s.result.get("is_malicious")]
        if malicious:
            names = ", ".join(f"{r['indicator']} ({r['confidence']} confidence)" for r in malicious)
            parts.append(f"Known-malicious indicators observed: {names}.")

        suspicious_process = next(
            (s.result for s in steps if s.call.tool == "process_reputation_lookup" and s.result.get("is_suspicious")),
            None,
        )
        if suspicious_process:
            parts.append(
                f"Process activity matched suspicious patterns: {', '.join(suspicious_process['matched_patterns'])}."
            )

        deviation = next(
            (s.result for s in steps if s.call.tool == "user_baseline_check" and s.result.get("is_deviation")),
            None,
        )
        if deviation:
            parts.append(
                f"User {deviation['user']} logged into {deviation['hostname']}, outside their normal "
                f"host baseline ({', '.join(deviation['normal_hosts'])})."
            )

        techniques = [t for s in steps if s.call.tool == "attack_technique_lookup" for t in s.result.get("matches", [])]
        if techniques:
            names = ", ".join(f"{t['id']} {t['name']}" for t in techniques)
            parts.append(f"Findings map to MITRE ATT&CK techniques: {names}.")

        if not (malicious or suspicious_process or deviation):
            parts.append("No corroborating evidence surfaced across threat-intel, process, or baseline checks.")

        parts.append("Recommended actions: " + "; ".join(actions) + ".")
        return " ".join(parts)
