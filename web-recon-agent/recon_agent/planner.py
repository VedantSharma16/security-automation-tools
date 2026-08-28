"""Planners decide the agent's next move given the transcript so far.

Two implementations, same interface (``plan(step_index, transcript) ->
AgentAction | Finish``):

- ``DeterministicPlanner`` — a fixed, explainable recon sequence with a
  couple of conditional branches (skip TLS on plain HTTP, only grade headers
  if the fetch succeeded). No LLM required; this is the default, and the
  fallback whenever ``--llm-planner`` is requested without a usable API key.
- ``LLMPlanner`` — hands the transcript to Claude with the toolbox exposed
  as tool-use schemas and lets the model pick the next tool call (or decide
  to finish), producing a genuinely dynamic agent loop rather than a fixed
  pipeline with an LLM bolted on at the end.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

from ._anthropic_util import DEFAULT_MODEL, get_client
from .tools import COMMON_PORTS


@dataclass
class AgentAction:
    tool: str
    kwargs: dict = field(default_factory=dict)
    thought: str = ""


@dataclass
class Finish:
    thought: str


class DeterministicPlanner:
    def __init__(self, target: str):
        self.target = target
        parsed = urlparse(target)
        self.host = parsed.hostname or target
        self.scheme = parsed.scheme or "https"
        self.port = parsed.port

    def plan(self, step_index, transcript):
        done = {step.action.tool for step in transcript}
        by_tool = {step.action.tool: step for step in transcript}

        if "dns_lookup" not in done:
            return AgentAction("dns_lookup", {"host": self.host}, "Resolve the target host before probing it.")

        if "fetch_headers" not in done:
            return AgentAction("fetch_headers", {"url": self.target}, "Fetch HTTP response headers from the target.")

        headers_step = by_tool.get("fetch_headers")
        if headers_step and headers_step.result.ok and "grade_security_headers" not in done:
            return AgentAction(
                "grade_security_headers",
                {"headers": headers_step.result.data["headers"], "scheme": self.scheme},
                "Evaluate the hardening of the response's security headers.",
            )

        if "fetch_robots_txt" not in done:
            return AgentAction("fetch_robots_txt", {"url": self.target}, "Check robots.txt for disclosed paths.")

        if self.scheme == "https" and "check_tls" not in done:
            return AgentAction(
                "check_tls",
                {"host": self.host, "port": self.port or 443},
                "Inspect the TLS configuration since the target is served over HTTPS.",
            )

        if "port_scan" not in done:
            ports = sorted(set(COMMON_PORTS) | ({self.port} if self.port else set()))
            return AgentAction(
                "port_scan", {"host": self.host, "ports": ports}, "Check for unexpectedly exposed common service ports."
            )

        return Finish("All planned recon steps are complete.")


SYSTEM_PROMPT = (
    "You are an autonomous, authorized web-recon agent. You have a fixed set of "
    "passive/lightweight tools. Pick exactly one tool to run next based on what has "
    "already been observed, or call 'finish' once you have enough information "
    "(host resolution, headers, security-header grading, robots.txt, TLS if HTTPS, "
    "and a light port check). Never repeat a tool that already succeeded. Stop "
    "within a handful of steps — do not over-scan."
)

TOOL_SCHEMAS = [
    {
        "name": "dns_lookup",
        "description": "Resolve the target host to its IP address(es).",
        "input_schema": {"type": "object", "properties": {"host": {"type": "string"}}, "required": ["host"]},
    },
    {
        "name": "fetch_headers",
        "description": "Fetch HTTP response headers (and status) from a URL.",
        "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
    },
    {
        "name": "grade_security_headers",
        "description": "Grade the most recently fetched HTTP response headers for security hardening.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "fetch_robots_txt",
        "description": "Fetch and parse robots.txt from the target's origin.",
        "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
    },
    {
        "name": "check_tls",
        "description": "Inspect the TLS/SSL configuration of an HTTPS host (protocol, cipher, certificate).",
        "input_schema": {
            "type": "object",
            "properties": {"host": {"type": "string"}, "port": {"type": "integer"}},
            "required": ["host"],
        },
    },
    {
        "name": "port_scan",
        "description": "TCP-connect scan a short list of common service ports.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "ports": {"type": "array", "items": {"type": "integer"}},
            },
            "required": ["host"],
        },
    },
    {
        "name": "finish",
        "description": "Stop recon; enough information has been gathered.",
        "input_schema": {"type": "object", "properties": {"reason": {"type": "string"}}, "required": ["reason"]},
    },
]


def _summarize_step(step) -> str:
    outcome = "ok" if step.result.ok else f"failed ({step.result.error})"
    return f"step {step.index}: {step.action.tool}({step.action.kwargs}) -> {outcome}: {step.result.data}"


class LLMPlanner:
    """Dynamic planner: Claude picks the next tool call via tool-use."""

    def __init__(self, target: str, api_key: str | None = None, model: str = DEFAULT_MODEL):
        self.target = target
        self.model = model
        self._client = get_client(api_key)

    @property
    def is_live(self) -> bool:
        return self._client is not None

    def plan(self, step_index, transcript):
        if self._client is None:
            raise RuntimeError("LLMPlanner requires ANTHROPIC_API_KEY and the anthropic package to be installed.")

        transcript_text = "\n".join(_summarize_step(s) for s in transcript) or "(no steps taken yet)"
        prompt = f"Target: {self.target}\n\nSteps so far:\n{transcript_text}\n\nChoose the next tool call."

        response = self._client.messages.create(
            model=self.model,
            max_tokens=300,
            system=SYSTEM_PROMPT,
            tools=TOOL_SCHEMAS,
            tool_choice={"type": "any"},
            messages=[{"role": "user", "content": prompt}],
        )

        for block in response.content:
            if getattr(block, "type", "") == "tool_use":
                if block.name == "finish":
                    return Finish(block.input.get("reason", "LLM decided recon is complete."))
                return AgentAction(block.name, dict(block.input), f"LLM selected tool '{block.name}'.")
        return Finish("LLM returned no tool call; stopping.")
