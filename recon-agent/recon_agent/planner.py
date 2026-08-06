"""Recon planning: a deterministic static plan, and an optional agentic
tool-selection loop driven by Claude's tool-use API.

Both paths execute the exact same underlying tools (see `tools/`); the only
difference is *who decides which tool to call next, and when to stop*. The
static plan runs by default and in every test — fully deterministic, no LLM
required. The agentic loop is opt-in (`--agentic`, requires
ANTHROPIC_API_KEY) and demonstrates a real tool-calling agent: Claude sees
each tool's result before deciding the next action, rather than following a
fixed script, and writes the final narrative itself once it stops calling
tools.
"""
from __future__ import annotations

import json
from typing import Callable, Dict, List, Tuple

from .models import ToolResult

STATIC_PLAN = ["dns_lookup", "http_headers", "tls_certificate", "robots_txt"]

TOOL_SPECS = [
    {
        "name": "dns_lookup",
        "description": "Resolve A/AAAA/MX/NS/TXT/DMARC DNS records for the target domain.",
    },
    {
        "name": "http_headers",
        "description": "Fetch the target over HTTP(S) and analyze security-relevant response headers and cookies.",
    },
    {
        "name": "tls_certificate",
        "description": "Inspect the target's TLS certificate: expiry, issuer, SANs, and negotiated protocol version.",
    },
    {
        "name": "robots_txt",
        "description": "Fetch robots.txt and flag disallowed paths that hint at sensitive functionality.",
    },
]

Registry = Dict[str, Callable[[], ToolResult]]


def static_plan() -> List[str]:
    return list(STATIC_PLAN)


def run_static(registry: Registry) -> List[ToolResult]:
    return [registry[name]() for name in static_plan() if name in registry]


def run_agentic(
    registry: Registry,
    target: str,
    max_steps: int = 6,
    client=None,
) -> Tuple[List[ToolResult], str]:
    """Let Claude choose which recon tools to run against `target`, one at a
    time, until it stops requesting tools or `max_steps` is hit. Returns
    (tool_results, narrative_text). Falls back to the static plan with no
    narrative if no client/API key is available.
    """
    if client is None:
        client = _build_client()
    if client is None:
        return run_static(registry), ""

    tools_schema = [
        {
            "name": spec["name"],
            "description": spec["description"],
            "input_schema": {"type": "object", "properties": {}},
        }
        for spec in TOOL_SPECS
    ]

    messages = [
        {
            "role": "user",
            "content": (
                f"You are a passive recon agent auditing '{target}', which the operator has "
                "confirmed they are authorized to test. Call recon tools one at a time to "
                "gather information about its security posture. Call each tool at most once. "
                "Once you've gathered what you need, stop calling tools and write a short "
                "analyst summary of the findings, in priority order."
            ),
        }
    ]

    results: List[ToolResult] = []
    called: set = set()
    narrative = ""

    for _ in range(max_steps):
        response = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=1024,
            tools=tools_schema,
            messages=messages,
        )
        messages.append({"role": "assistant", "content": response.content})

        text_blocks = [b.text for b in response.content if getattr(b, "type", None) == "text"]
        if text_blocks:
            narrative = " ".join(text_blocks).strip()

        tool_uses = [b for b in response.content if getattr(b, "type", None) == "tool_use"]
        if not tool_uses:
            break

        tool_results_content = []
        for block in tool_uses:
            name = block.name
            if name in registry and name not in called:
                called.add(name)
                result = registry[name]()
                results.append(result)
                payload = json.dumps(result.data, default=str)[:4000]
            else:
                payload = json.dumps({"note": "tool already run or unknown"})
            tool_results_content.append(
                {"type": "tool_result", "tool_use_id": block.id, "content": payload}
            )
        messages.append({"role": "user", "content": tool_results_content})

        if response.stop_reason != "tool_use":
            break

    return results, narrative


def _build_client():
    import os

    try:
        import anthropic
    except ImportError:
        return None

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    return anthropic.Anthropic(api_key=api_key)
