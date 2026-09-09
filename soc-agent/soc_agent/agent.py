"""The agent orchestrator: a bounded tool-calling (ReAct-style) loop.

In live mode, the loop hands the LLM a system prompt, the alert, and the
tool specs, then repeatedly executes whatever tool(s) it asks for and
feeds the results back — the standard "reason, act, observe" pattern —
until it calls ``finish_investigation`` or a step cap is hit. The step
cap is not cosmetic: an agent that can call tools in a loop can also loop
forever (or run up an API bill) if it never converges on an answer, so
the orchestrator treats "ran out of steps" as a first-class failure mode
rather than trusting the model to always terminate.

Without an API key, :meth:`SocAgent.investigate` falls back to the
deterministic offline planner (see :mod:`soc_agent.offline_planner`),
which drives the exact same tools through scripted logic — matching the
offline-first pattern used throughout this repo, so the CLI, tests, and
examples all work without any credentials.
"""

from __future__ import annotations

import json
import os

from .offline_planner import run_offline_investigation
from .tools import TOOL_DISPATCH, TOOL_SPECS, ToolContext, Verdict

DEFAULT_MODEL = "claude-sonnet-5"
DEFAULT_MAX_STEPS = 8

SYSTEM_PROMPT = (
    "You are an autonomous SOC tier-1 triage agent. You will be given a raw "
    "security alert. Investigate it using the tools available to you before "
    "drawing any conclusion: check indicators against threat intel, search "
    "any provided host logs, look up relevant MITRE ATT&CK techniques, and "
    "check suspicious process names against the host baseline. Only call "
    "tools that are relevant to this specific alert. Once you have enough "
    "evidence, call finish_investigation exactly once, as your final action, "
    "with a structured verdict. Do not call finish_investigation before "
    "gathering at least one piece of supporting evidence unless the alert "
    "contains no investigable indicators at all."
)


class InvestigationIncomplete(RuntimeError):
    """Raised when the agent exhausts its step budget without concluding."""


class SocAgent:
    """Investigates a security alert by calling tools in a loop, live or offline."""

    def __init__(self, api_key: str | None = None, model: str = DEFAULT_MODEL, max_steps: int = DEFAULT_MAX_STEPS):
        self.model = model
        self.max_steps = max_steps
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

    def investigate(self, alert_text: str, log_path: str | None = None):
        """Investigate ``alert_text``, returning ``(Verdict, transcript)``.

        ``transcript`` is a list of step objects, each exposing ``.tool``,
        ``.arguments``, ``.result`` and a ``to_dict()`` method.
        """
        ctx = ToolContext.load_default(log_path=log_path)
        if self.is_live:
            return self._investigate_live(alert_text, ctx)
        return run_offline_investigation(alert_text, ctx, max_steps=self.max_steps)

    def _investigate_live(self, alert_text: str, ctx: ToolContext):
        messages = [{"role": "user", "content": f"Investigate this alert:\n\n{alert_text}"}]
        transcript: list[_LiveStep] = []

        for _ in range(self.max_steps):
            response = self._client.messages.create(
                model=self.model,
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                tools=TOOL_SPECS,
                messages=messages,
            )
            messages.append({"role": "assistant", "content": response.content})

            tool_uses = [block for block in response.content if getattr(block, "type", "") == "tool_use"]
            if not tool_uses:
                break

            tool_results = []
            finished_verdict = None
            for use in tool_uses:
                result = TOOL_DISPATCH[use.name](ctx, **use.input)
                transcript.append(_LiveStep(use.name, use.input, result))
                if use.name == "finish_investigation":
                    finished_verdict = result
                tool_results.append(
                    {"type": "tool_result", "tool_use_id": use.id, "content": json.dumps(result, default=str)}
                )
            messages.append({"role": "user", "content": tool_results})

            if finished_verdict is not None:
                return Verdict(**finished_verdict, steps_taken=len(transcript)), transcript

        raise InvestigationIncomplete(
            f"Agent did not call finish_investigation within {self.max_steps} steps "
            f"({len(transcript)} tool calls made)."
        )


class _LiveStep:
    """Mirrors offline_planner.Step's interface so callers don't need to branch."""

    __slots__ = ("tool", "arguments", "result")

    def __init__(self, tool: str, arguments: dict, result: dict):
        self.tool = tool
        self.arguments = arguments
        self.result = result

    def to_dict(self) -> dict:
        return {"tool": self.tool, "arguments": self.arguments, "result": self.result}
