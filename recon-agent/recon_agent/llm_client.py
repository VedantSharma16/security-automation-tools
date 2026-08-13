"""Optional Claude-driven planning and narrative generation.

Two independent pieces of LLM integration live here, both with an offline
fallback so the package is fully runnable and testable without an API key:

- `LLMPlanner` — drives the agent loop itself. It hands Claude the same five
  tools `DeterministicPlanner` uses (via native tool-use) and lets the model
  decide, one step at a time, what to call next. This is the actual
  "agentic pipeline" — the model is choosing actions from observations, not
  filling in a template.
- `generate_narrative()` — writes the human-readable executive-summary
  paragraph for the final report from the structured run results. Falls
  back to a deterministic template when no API key/SDK is available.
"""

from __future__ import annotations

import json
import os

from .agent import Action

DEFAULT_MODEL = "claude-sonnet-5"

PLANNER_SYSTEM_PROMPT = (
    "You are an authorized penetration-testing recon agent. You have "
    "read-only reconnaissance tools: tcp_connect_scan, grab_banner, "
    "http_headers, tls_cert_info, and vuln_lookup. Investigate the target "
    "methodically: scan first, fingerprint every open port you find, pull "
    "the TLS certificate on any HTTPS port, and look up known "
    "vulnerabilities for each service/version you identify. Call `finish` "
    "once every open port has been fingerprinted and checked. Never guess "
    "at a service or version you have not actually fingerprinted."
)

TOOL_SCHEMAS = [
    {
        "name": "tcp_connect_scan",
        "description": "TCP connect scan of the target over a curated list of common ports.",
        "input_schema": {
            "type": "object",
            "properties": {"host": {"type": "string"}},
            "required": ["host"],
        },
    },
    {
        "name": "grab_banner",
        "description": "Connect to a specific open port and read its startup banner.",
        "input_schema": {
            "type": "object",
            "properties": {"host": {"type": "string"}, "port": {"type": "integer"}},
            "required": ["host", "port"],
        },
    },
    {
        "name": "http_headers",
        "description": "Send an HTTP GET / and return the response status line and headers.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "integer"},
                "use_tls": {"type": "boolean"},
            },
            "required": ["host", "port"],
        },
    },
    {
        "name": "tls_cert_info",
        "description": "Inspect the TLS certificate presented on a given port.",
        "input_schema": {
            "type": "object",
            "properties": {"host": {"type": "string"}, "port": {"type": "integer"}},
            "required": ["host", "port"],
        },
    },
    {
        "name": "vuln_lookup",
        "description": "Look up known CVEs for a fingerprinted service name and version in the local knowledge base.",
        "input_schema": {
            "type": "object",
            "properties": {
                "service": {"type": "string"},
                "version": {"type": "string"},
                "port": {"type": "integer"},
            },
            "required": ["service"],
        },
    },
    {
        "name": "finish",
        "description": "Call once recon is complete and no further tool calls are needed.",
        "input_schema": {"type": "object", "properties": {"summary": {"type": "string"}}, "required": []},
    },
]


class LLMNotAvailable(RuntimeError):
    """Raised if next_action() is called on an LLMPlanner with no live client."""


class LLMPlanner:
    """A planner driven by Claude's native tool-use, one decision at a time."""

    def __init__(self, api_key: str | None = None, model: str = DEFAULT_MODEL):
        self.model = model
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._client = None
        self._messages: list = []
        self._pending_tool_use_id: str | None = None
        if self.api_key:
            try:
                import anthropic  # type: ignore

                self._client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                self._client = None

    @property
    def is_live(self) -> bool:
        return self._client is not None

    def start(self, target: str) -> None:
        self._messages = [{"role": "user", "content": f"Begin authorized recon against target: {target}"}]

    def next_action(self, state) -> Action | None:
        if not self.is_live:
            raise LLMNotAvailable("No ANTHROPIC_API_KEY / anthropic SDK available.")

        response = self._client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=PLANNER_SYSTEM_PROMPT,
            tools=TOOL_SCHEMAS,
            messages=self._messages,
        )
        self._messages.append({"role": "assistant", "content": response.content})

        tool_use = next((b for b in response.content if getattr(b, "type", "") == "tool_use"), None)
        if tool_use is None or tool_use.name == "finish":
            return None

        self._pending_tool_use_id = tool_use.id
        return Action(tool=tool_use.name, args=dict(tool_use.input or {}), reason="LLM tool call")

    def observe(self, result: dict) -> None:
        self._messages.append(
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": self._pending_tool_use_id,
                        "content": json.dumps(result, default=str),
                    }
                ],
            }
        )


NARRATIVE_SYSTEM_PROMPT = (
    "You are a penetration tester writing the executive-summary section of "
    "a recon report for a client. Be concise and factual, and only "
    "reference findings actually present in the data given — never "
    "speculate about vulnerabilities that were not looked up."
)


def _build_narrative_prompt(run_summary: dict) -> str:
    lines = [
        f"Target: {run_summary['target']}",
        f"Overall risk: {run_summary['risk'].upper()}",
        f"Open ports: {run_summary['open_ports']}",
    ]
    if run_summary["vuln_matches"]:
        lines.append("Vulnerability matches:")
        for m in run_summary["vuln_matches"]:
            lines.append(f"- {m['cve']} ({m['severity']}) on port {m['port']}: {m['description']}")
    else:
        lines.append("No known-CVE matches for the fingerprinted services.")
    return "\n".join(lines)


def _offline_narrative(run_summary: dict) -> str:
    parts = ["[offline heuristic summary — set ANTHROPIC_API_KEY for LLM-generated analysis]"]
    parts.append(f"Overall risk: {run_summary['risk'].upper()}.")
    parts.append(f"{len(run_summary['open_ports'])} open port(s) discovered on {run_summary['target']}.")
    if run_summary["vuln_matches"]:
        cves = ", ".join(sorted({m["cve"] for m in run_summary["vuln_matches"]}))
        parts.append(f"Potential known-vulnerability matches: {cves}. Verify manually before reporting to a client.")
    else:
        parts.append("No known-CVE matches for the fingerprinted service banners.")
    parts.append(
        "Recommended next steps: manually verify each finding, check authentication on any exposed "
        "database/management ports, and confirm patch levels against vendor advisories before escalating."
    )
    return " ".join(parts)


def generate_narrative(run_summary: dict, api_key: str | None = None, model: str = DEFAULT_MODEL) -> str:
    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if api_key:
        try:
            import anthropic  # type: ignore

            client = anthropic.Anthropic(api_key=api_key)
            response = client.messages.create(
                model=model,
                max_tokens=500,
                system=NARRATIVE_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": _build_narrative_prompt(run_summary)}],
            )
            return "".join(b.text for b in response.content if getattr(b, "type", "") == "text").strip()
        except Exception as exc:  # pragma: no cover - network/SDK failure path
            return _offline_narrative(run_summary) + f"\n\n[LLM call failed, offline fallback used: {exc}]"
    return _offline_narrative(run_summary)
