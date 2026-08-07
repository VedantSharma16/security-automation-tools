"""Live agent loop: Claude tool-calling (ReAct-style) over the alert.

This is the "live" half of the agent. It runs a real multi-turn tool-use
loop against the Claude API — the model decides which tools to call, reads
back the observations, and iterates until it either has enough evidence to
answer or the step budget runs out. See ``agent.py`` for the offline
deterministic fallback that mirrors the same trace shape without needing an
API key.
"""

from __future__ import annotations

import json
import os

from .tools import TOOL_FUNCTIONS, TOOL_SCHEMAS

DEFAULT_MODEL = "claude-sonnet-5"
DEFAULT_MAX_STEPS = 6

SYSTEM_PROMPT = (
    "You are an autonomous SOC tier-2 analyst agent investigating a single "
    "security alert. You have tools to check IP/domain reputation, WHOIS "
    "age, GeoIP/hosting info, process baseline status, and to search a "
    "MITRE ATT&CK technique reference. Call tools to gather evidence before "
    "concluding — do not guess at reputation or WHOIS data yourself. Use "
    "as few tool calls as the evidence allows (typically 2-6). "
    "\n\n"
    "Once you have enough evidence, STOP calling tools and respond with "
    "ONLY a single JSON object (no prose, no markdown fences) with exactly "
    "these keys: "
    '"verdict" (one of "malicious", "suspicious", "benign", "inconclusive"), '
    '"severity" (one of "low", "medium", "high", "critical"), '
    '"confidence" (one of "low", "medium", "high"), '
    '"summary" (2-4 sentences explaining the verdict using the evidence '
    "gathered), and "
    '"recommended_actions" (a list of 2-4 concrete next steps for the '
    "on-call analyst)."
)


def is_available(api_key: str | None) -> bool:
    """Return True if live mode can run: a key is present and the SDK is installed."""
    if not api_key:
        return False
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False
    return True


def _extract_text(content_blocks) -> str:
    return "".join(b.text for b in content_blocks if getattr(b, "type", "") == "text").strip()


def _extract_tool_uses(content_blocks) -> list:
    return [b for b in content_blocks if getattr(b, "type", "") == "tool_use"]


def _parse_final_answer(text: str) -> dict | None:
    """Parse the model's final JSON verdict, tolerating stray markdown fences."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.startswith("json"):
            cleaned = cleaned[4:]
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        return None
    required = {"verdict", "severity", "confidence", "summary", "recommended_actions"}
    if not required.issubset(parsed.keys()):
        return None
    return parsed


def run_live_agent(alert_text: str, api_key: str, model: str = DEFAULT_MODEL, max_steps: int = DEFAULT_MAX_STEPS):
    """Run the Claude tool-calling ReAct loop. Returns (steps, verdict_dict).

    ``steps`` is a list of raw step dicts (step, thought, action,
    action_input, observation) — the caller (agent.py) wraps these into
    ``AgentStep`` objects to keep this module free of the dataclass import
    cycle. ``verdict_dict`` is None if the agent exhausted its step budget
    without producing a valid final answer.
    """
    import anthropic

    client = anthropic.Anthropic(api_key=api_key)
    messages = [
        {
            "role": "user",
            "content": (
                "Investigate the following security alert and determine "
                f"whether it represents real malicious activity.\n\n{alert_text}"
            ),
        }
    ]

    steps = []
    step_num = 0
    verdict = None

    for _ in range(max_steps):
        response = client.messages.create(
            model=model,
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            tools=TOOL_SCHEMAS,
            messages=messages,
        )
        messages.append({"role": "assistant", "content": response.content})

        thought = _extract_text(response.content)
        tool_uses = _extract_tool_uses(response.content)

        if not tool_uses:
            verdict = _parse_final_answer(thought)
            break

        tool_result_blocks = []
        for tu in tool_uses:
            step_num += 1
            fn = TOOL_FUNCTIONS.get(tu.name)
            try:
                observation = fn(**tu.input) if fn is not None else {"error": f"unknown tool: {tu.name}"}
            except Exception as exc:  # pragma: no cover - defensive, tool args from the model
                observation = {"error": str(exc)}
            steps.append(
                {
                    "step": step_num,
                    "thought": thought,
                    "action": tu.name,
                    "action_input": tu.input,
                    "observation": observation,
                }
            )
            tool_result_blocks.append(
                {"type": "tool_result", "tool_use_id": tu.id, "content": json.dumps(observation)}
            )
        messages.append({"role": "user", "content": tool_result_blocks})

    return steps, verdict


def resolve_api_key(explicit_key: str | None = None) -> str | None:
    return explicit_key or os.environ.get("ANTHROPIC_API_KEY")
