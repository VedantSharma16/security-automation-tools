"""The agent's tool registry: one entry per action the agent can take.

Each tool pairs a JSON schema (the same shape an LLM tool-use API expects)
with a Python callable. Keeping schema and implementation side by side
means the deterministic planner and the LLM planner both dispatch through
exactly the same executable tools — there is only one code path that
actually touches the network.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from . import header_analyzer
from .models import ProbeResult


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    input_schema: dict
    func: Callable


def _probe_https(state, args: dict) -> ProbeResult:
    return state.probe_url_fn(f"https://{args['host']}", timeout=state.timeout)


def _probe_http(state, args: dict) -> ProbeResult:
    return state.probe_url_fn(f"http://{args['host']}", timeout=state.timeout)


def _probe_tls(state, args: dict):
    return state.probe_tls_fn(args["host"], port=args.get("port", 443), timeout=state.timeout)


def _analyze_headers(state, args: dict):
    probe = state.probes.get(args["probe_key"])
    if probe is None:
        return []
    return header_analyzer.analyze_headers(probe)


def _finish(state, args: dict):
    return {"summary": args.get("summary", "")}


TOOLS: dict[str, Tool] = {
    tool.name: tool
    for tool in (
        Tool(
            name="probe_https",
            description="Send a single GET request to https://{host}/ and capture status, headers, and timing.",
            input_schema={
                "type": "object",
                "properties": {"host": {"type": "string"}},
                "required": ["host"],
            },
            func=_probe_https,
        ),
        Tool(
            name="probe_http",
            description="Send a single GET request to http://{host}/ and capture status, headers, and timing. "
            "Use when the HTTPS probe failed, to check for an unencrypted fallback.",
            input_schema={
                "type": "object",
                "properties": {"host": {"type": "string"}},
                "required": ["host"],
            },
            func=_probe_http,
        ),
        Tool(
            name="probe_tls",
            description="Perform a TLS handshake against host:port and report the negotiated protocol "
            "version and certificate expiry.",
            input_schema={
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "port": {"type": "integer", "default": 443},
                },
                "required": ["host"],
            },
            func=_probe_tls,
        ),
        Tool(
            name="analyze_headers",
            description="Run the security-header rule set against a previously captured probe result, "
            "identified by its probe_key (e.g. 'https' or 'http').",
            input_schema={
                "type": "object",
                "properties": {"probe_key": {"type": "string"}},
                "required": ["probe_key"],
            },
            func=_analyze_headers,
        ),
        Tool(
            name="finish",
            description="Declare the recon pass complete. Call this once no further probe would add signal.",
            input_schema={
                "type": "object",
                "properties": {"summary": {"type": "string"}},
                "required": [],
            },
            func=_finish,
        ),
    )
}


def tool_schemas() -> list[dict]:
    """Anthropic tool-use formatted schema list, for the LLM planner."""
    return [{"name": t.name, "description": t.description, "input_schema": t.input_schema} for t in TOOLS.values()]
