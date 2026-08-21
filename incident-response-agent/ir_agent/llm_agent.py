"""LLM-driven agent loop using native Anthropic tool use (function calling).

This is the "live" planner: the model itself decides, turn by turn, which
tool to call next (or when to stop), based on the observations returned so
far. It's a genuine multi-step tool-orchestration loop rather than a
single-shot prompt — the model can chain lookups (e.g. check an IP, then
based on that decide whether the CVE mentioned nearby is worth checking too)
before committing to a final, structured verdict via the ``finish`` tool.

Requires ``ANTHROPIC_API_KEY`` and the ``anthropic`` package; without either,
:attr:`LLMAgent.is_live` is False and callers should use the offline planner
in :mod:`ir_agent.agent` instead.
"""

from __future__ import annotations

import os

from ir_agent.models import AgentStep, IncidentVerdict, ToolResult
from ir_agent.synthesis import synthesize_verdict
from ir_agent.tools import IntelStore, TOOL_FUNCTIONS, default_store

DEFAULT_MODEL = "claude-sonnet-5"

SYSTEM_PROMPT = (
    "You are an incident-response triage agent. You investigate a security "
    "incident by calling the tools available to you (IP reputation, domain "
    "reputation, CVE lookup, ATT&CK technique lookup) to gather evidence "
    "before drawing conclusions. Only cite findings that came from a tool "
    "observation — never invent reputation data, CVE details, or technique "
    "matches. Investigate every IP, domain, and CVE mentioned in the "
    "incident text before finishing. Call the `finish` tool exactly once, "
    "when you have enough evidence, with your final structured verdict."
)

TOOLS = [
    {
        "name": "check_ip_reputation",
        "description": "Look up an IPv4 address against the local threat-intel feed of known-malicious indicators.",
        "input_schema": {
            "type": "object",
            "properties": {"ip": {"type": "string", "description": "The IPv4 address to check."}},
            "required": ["ip"],
        },
    },
    {
        "name": "check_domain_reputation",
        "description": "Look up a domain against the local threat-intel feed of known-malicious indicators.",
        "input_schema": {
            "type": "object",
            "properties": {"domain": {"type": "string", "description": "The domain name to check."}},
            "required": ["domain"],
        },
    },
    {
        "name": "check_cve",
        "description": "Look up a CVE ID in the local CVE database for its CVSS score, severity, and exploitation status.",
        "input_schema": {
            "type": "object",
            "properties": {"cve_id": {"type": "string", "description": "The CVE identifier, e.g. CVE-2021-44228."}},
            "required": ["cve_id"],
        },
    },
    {
        "name": "lookup_attack_technique",
        "description": "Match a piece of incident text against bundled MITRE ATT&CK technique keywords.",
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string", "description": "Text to match against ATT&CK technique keywords."}},
            "required": ["query"],
        },
    },
    {
        "name": "finish",
        "description": "Deliver the final triage verdict once enough evidence has been gathered. Call exactly once.",
        "input_schema": {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                "summary": {"type": "string", "description": "2-4 sentence analyst summary grounded in tool observations."},
                "recommended_actions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Concrete next steps for the on-call analyst.",
                },
            },
            "required": ["severity", "confidence", "summary", "recommended_actions"],
        },
    },
]

_INPUT_KEY_BY_TOOL = {
    "check_ip_reputation": "ip",
    "check_domain_reputation": "domain",
    "check_cve": "cve_id",
    "lookup_attack_technique": "query",
}


class LLMAgent:
    """Wraps an Anthropic tool-use loop with a graceful offline-unavailable state."""

    def __init__(self, api_key: str | None = None, model: str | None = None):
        self.model = model or DEFAULT_MODEL
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

    def run(self, incident_text: str, max_steps: int, store: IntelStore | None = None) -> IncidentVerdict:
        if not self.is_live:
            raise RuntimeError("LLMAgent.run() called without a live Anthropic client.")
        store = store or default_store()

        messages = [{"role": "user", "content": f"Incident report:\n\n{incident_text}"}]
        trace: list[AgentStep] = []
        evidence: list[ToolResult] = []

        for step_num in range(1, max_steps + 1):
            response = self._client.messages.create(
                model=self.model,
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                tools=TOOLS,
                messages=messages,
            )
            messages.append({"role": "assistant", "content": response.content})

            tool_uses = [block for block in response.content if getattr(block, "type", "") == "tool_use"]
            if not tool_uses:
                break

            finish_block = next((b for b in tool_uses if b.name == "finish"), None)
            tool_result_content = []

            for block in tool_uses:
                if block.name == "finish":
                    continue
                thought = self._extract_thought(response)
                observation = self._call_tool(block.name, block.input, store)
                trace.append(AgentStep(step=step_num, thought=thought, tool=block.name, tool_input=str(block.input), observation=observation))
                evidence.append(observation)
                tool_result_content.append(
                    {"type": "tool_result", "tool_use_id": block.id, "content": observation.summary}
                )

            if finish_block:
                trace.append(
                    AgentStep(
                        step=step_num,
                        thought="Sufficient evidence gathered; delivering final verdict.",
                        tool="finish",
                        tool_input="",
                        observation=None,
                    )
                )
                return self._verdict_from_finish(finish_block.input, evidence, trace)

            messages.append({"role": "user", "content": tool_result_content})

        # Ran out of steps (or the model stopped without calling finish): synthesize
        # a verdict deterministically from whatever evidence the model gathered.
        verdict = synthesize_verdict(incident_text, evidence, trace, llm_backed=True)
        verdict.summary += " [LLM planner did not call finish within max_steps; verdict synthesized from partial evidence.]"
        return verdict

    @staticmethod
    def _extract_thought(response) -> str:
        text_blocks = [b.text for b in response.content if getattr(b, "type", "") == "text"]
        return " ".join(text_blocks).strip() or "(model issued a tool call without accompanying reasoning text)"

    @staticmethod
    def _call_tool(name: str, tool_input: dict, store: IntelStore) -> ToolResult:
        fn = TOOL_FUNCTIONS.get(name)
        if fn is None:
            return ToolResult(tool=name, tool_input=str(tool_input), malicious=False, summary=f"Unknown tool '{name}'.")
        key = _INPUT_KEY_BY_TOOL[name]
        return fn(tool_input.get(key, ""), store)

    @staticmethod
    def _verdict_from_finish(finish_input: dict, evidence: list[ToolResult], trace: list[AgentStep]) -> IncidentVerdict:
        return IncidentVerdict(
            severity=finish_input.get("severity", "low"),
            confidence=float(finish_input.get("confidence", 0.5)),
            summary=finish_input.get("summary", ""),
            recommended_actions=list(finish_input.get("recommended_actions", [])),
            evidence=evidence,
            trace=trace,
            llm_backed=True,
        )
