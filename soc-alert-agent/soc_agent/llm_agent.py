"""LLM-driven agentic loop using the Anthropic Messages API's native tool use.

Unlike the fixed pipelines elsewhere in this repo, this is a real ReAct-style
agent: the model decides which tool to call and when, sees each tool's
result, and keeps going until it calls one of the terminal tools
(``escalate`` / ``monitor`` / ``close``) or a step budget is hit. Every step
is dispatched through the same :class:`~soc_agent.tools.ToolRegistry` the
deterministic planner uses, so both backends produce directly comparable
:class:`~soc_agent.models.AgentResult` objects.
"""

from __future__ import annotations

import json

from .models import Alert, AgentResult, AgentStep
from .tools import TERMINAL_TOOLS, TOOL_SCHEMAS, ToolRegistry

DEFAULT_MODEL = "claude-sonnet-5"

SYSTEM_PROMPT = (
    "You are an autonomous SOC tier-1 triage agent. You will be given one alert "
    "and a set of tools to investigate it: checking indicator reputation, asset "
    "criticality, related alerts in the queue, and relevant MITRE ATT&CK "
    "techniques. Use tools to gather evidence before deciding — do not guess. "
    "When you have enough evidence, call exactly one of the terminal tools "
    "(escalate, monitor, close) with a reason grounded in the tool results you "
    "observed. Call each tool at most once per distinct argument. Keep your "
    "reasoning brief between tool calls."
)


def _alert_kickoff_prompt(alert: Alert) -> str:
    return (
        "Investigate and triage the following alert:\n\n"
        f"{json.dumps(alert.to_dict(), indent=2)}"
    )


def run_llm(
    alert: Alert,
    tools: ToolRegistry,
    api_key: str,
    model: str = DEFAULT_MODEL,
    max_steps: int = 8,
) -> AgentResult:
    import anthropic  # imported lazily so it's a true optional dependency

    client = anthropic.Anthropic(api_key=api_key)
    messages: list[dict] = [{"role": "user", "content": _alert_kickoff_prompt(alert)}]
    steps: list[AgentStep] = []

    for step_no in range(1, max_steps + 1):
        response = client.messages.create(
            model=model,
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            tools=TOOL_SCHEMAS,
            messages=messages,
        )
        messages.append({"role": "assistant", "content": response.content})

        thought = "".join(b.text for b in response.content if getattr(b, "type", "") == "text").strip() or None
        tool_use_blocks = [b for b in response.content if getattr(b, "type", "") == "tool_use"]

        if not tool_use_blocks:
            # Model stopped without calling a terminal tool; treat as inconclusive.
            reason = thought or "Model ended the investigation without a terminal decision."
            return AgentResult(
                alert_id=alert.alert_id,
                verdict="monitor",
                reason=f"[no terminal tool call — defaulted to monitor] {reason}",
                steps=steps,
                backend="llm",
            )

        tool_results_content = []
        terminal_result = None
        for block in tool_use_blocks:
            result = tools.dispatch(block.name, block.input)
            steps.append(AgentStep(step_no, block.name, block.input, result, thought=thought))
            tool_results_content.append(
                {"type": "tool_result", "tool_use_id": block.id, "content": json.dumps(result)}
            )
            if block.name in TERMINAL_TOOLS:
                terminal_result = result

        if terminal_result is not None:
            return AgentResult(
                alert_id=alert.alert_id,
                verdict=terminal_result["verdict"],
                reason=terminal_result["reason"],
                steps=steps,
                backend="llm",
            )

        messages.append({"role": "user", "content": tool_results_content})

    return AgentResult(
        alert_id=alert.alert_id,
        verdict="monitor",
        reason=f"[step budget of {max_steps} exhausted without a terminal decision — defaulted to monitor]",
        steps=steps,
        backend="llm",
    )
