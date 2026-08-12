"""The agentic investigation loop.

When ``ANTHROPIC_API_KEY`` is set (and the ``anthropic`` package is
installed), :class:`SocAgent` runs a genuine ReAct-style tool-calling loop:
Claude decides which investigation tool to call next, sees the result, and
either calls another tool or calls ``submit_verdict`` to end the
investigation. This is a real agentic pipeline, not a fixed sequence of
steps — the model chooses its own path through the tools based on what it
learns.

Without a key, :meth:`SocAgent.investigate` falls back to
:mod:`soc_agent.planner`, a deterministic scripted investigation that uses
the same tools and produces a trace in the same shape, so the tool is
fully usable and testable offline.
"""

from __future__ import annotations

import json
import os

from . import planner
from .models import Alert, AgentResult, AgentStep, Verdict
from .tools import TOOLS, TOOL_SCHEMAS

DEFAULT_MODEL = "claude-sonnet-5"

SYSTEM_PROMPT = (
    "You are an autonomous SOC tier-1 triage agent. You will be given a "
    "security alert. Investigate it using the tools available to you: "
    "look up indicators against threat intel, resolve suspicious domains, "
    "cross-reference behavior against MITRE ATT&CK, search logs for "
    "corroborating activity, and check the criticality of affected assets. "
    "Call as many tools as you need, in whatever order makes sense given "
    "what you learn — you do not need to call every tool. When you have "
    "enough evidence, call submit_verdict exactly once with your final "
    "conclusion. Do not guess at indicator reputation yourself; always use "
    "ioc_lookup rather than assuming."
)


def _build_alert_prompt(alert: Alert) -> str:
    lines = [f"## Alert {alert.alert_id}: {alert.title}", "", alert.description.strip()]
    details = []
    if alert.source_ip:
        details.append(f"source_ip: {alert.source_ip}")
    if alert.destination:
        details.append(f"destination: {alert.destination}")
    if alert.user:
        details.append(f"user: {alert.user}")
    if alert.hostname:
        details.append(f"hostname: {alert.hostname}")
    if alert.raw_indicators:
        details.append(f"raw_indicators: {', '.join(alert.raw_indicators)}")
    if details:
        lines += ["", "## Structured fields", *[f"- {d}" for d in details]]
    return "\n".join(lines)


class SocAgent:
    """Runs a tool-calling investigation over a security alert."""

    def __init__(self, api_key: str | None = None, model: str = DEFAULT_MODEL, client=None):
        self.model = model
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._client = client
        if self._client is None and self.api_key:
            try:
                import anthropic  # type: ignore

                self._client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                self._client = None

    @property
    def is_live(self) -> bool:
        return self._client is not None

    def investigate(self, alert: Alert, max_steps: int = 8) -> AgentResult:
        if self._client is not None:
            try:
                return self._investigate_live(alert, max_steps)
            except Exception as exc:  # pragma: no cover - network/SDK failure path
                result = planner.run(alert, max_steps=max_steps)
                result.mode = "offline-after-live-error"
                result.verdict.rationale += f" [live agent call failed, offline planner used: {exc}]"
                return result
        return planner.run(alert, max_steps=max_steps)

    def _investigate_live(self, alert: Alert, max_steps: int) -> AgentResult:
        messages = [{"role": "user", "content": _build_alert_prompt(alert)}]
        trace: list[AgentStep] = []
        step_counter = 0

        for _ in range(max_steps):
            response = self._client.messages.create(
                model=self.model,
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                tools=TOOL_SCHEMAS,
                messages=messages,
            )
            content = list(response.content)
            messages.append({"role": "assistant", "content": content})

            tool_uses = [block for block in content if getattr(block, "type", None) == "tool_use"]
            if not tool_uses:
                # Model stopped without submitting a verdict; treat as inconclusive.
                break

            tool_results = []
            verdict = None
            for block in tool_uses:
                step_counter += 1
                if block.name == "submit_verdict":
                    verdict = Verdict(
                        verdict=block.input["verdict"],
                        confidence=float(block.input["confidence"]),
                        recommended_action=block.input["recommended_action"],
                        rationale=block.input["rationale"],
                    )
                    trace.append(AgentStep(step=step_counter, tool=block.name, input=block.input, output=None))
                    tool_results.append(
                        {"type": "tool_result", "tool_use_id": block.id, "content": "Verdict recorded."}
                    )
                    continue

                tool_fn = TOOLS.get(block.name)
                if tool_fn is None:  # pragma: no cover - defensive, model can't request unknown tools per schema
                    output = {"error": f"unknown tool {block.name}"}
                else:
                    output = tool_fn(**block.input)
                trace.append(AgentStep(step=step_counter, tool=block.name, input=block.input, output=output))
                tool_results.append(
                    {"type": "tool_result", "tool_use_id": block.id, "content": json.dumps(output)}
                )

            if verdict is not None:
                return AgentResult(alert=alert, trace=trace, verdict=verdict, mode="live")

            messages.append({"role": "user", "content": tool_results})

        fallback_verdict = Verdict(
            verdict="inconclusive",
            confidence=0.3,
            recommended_action="Escalate to a human analyst; the agent exhausted its step budget without a verdict.",
            rationale=f"Agent used all {max_steps} step(s) without calling submit_verdict.",
        )
        return AgentResult(alert=alert, trace=trace, verdict=fallback_verdict, mode="live-max-steps")
