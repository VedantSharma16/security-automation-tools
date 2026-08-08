"""Live agentic tool-calling loop, backed by the Claude API.

This is the "real" agent: Claude is given the tool registry from
``tools.py`` plus one extra tool, ``submit_verdict``, and is instructed to
call tools to gather evidence and then call ``submit_verdict`` to conclude
— a forced-tool-call pattern for getting reliable structured output instead
of parsing free text. The loop is bounded by ``max_iterations`` so a model
that never converges can't spin forever; when that happens the caller
(``engine.py``) falls back to the deterministic offline planner.

Requires ``ANTHROPIC_API_KEY`` and the ``anthropic`` package. Without
either, :attr:`LLMAgent.is_live` is ``False`` and callers should use
``planner.run`` instead — this module has no offline mode of its own by
design, so the two code paths stay clearly separated.
"""

from __future__ import annotations

import json
import os

from investigator import tools
from investigator.state import Alert, InvestigationResult, ToolCall

DEFAULT_MODEL = "claude-sonnet-5"
DEFAULT_MAX_ITERATIONS = 8

SYSTEM_PROMPT = (
    "You are a SOC tier-2 analyst agent investigating a single security alert. "
    "You have tools to check indicator reputation, asset criticality, prior alert "
    "history, and MITRE ATT&CK technique mapping. Call tools to gather evidence — "
    "you do not need to call every tool, only the ones relevant to reaching a "
    "confident verdict, and you should stop gathering evidence once it's conclusive. "
    "Always call calculate_risk_score with your aggregated signals before concluding. "
    "When you have enough evidence, call submit_verdict exactly once with your final "
    "verdict, confidence, risk score/band, a short summary, and recommended next "
    "steps. Do not call submit_verdict until you have called calculate_risk_score."
)

SUBMIT_VERDICT_TOOL = {
    "name": "submit_verdict",
    "description": "Submit the final investigation verdict. Call this exactly once, as the last tool call.",
    "input_schema": {
        "type": "object",
        "properties": {
            "verdict": {"type": "string", "enum": ["true_positive", "false_positive", "needs_escalation"]},
            "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
            "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
            "risk_band": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
            "summary": {"type": "string", "description": "2-4 sentence analyst summary of the investigation."},
            "recommended_actions": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["verdict", "confidence", "risk_score", "risk_band", "summary", "recommended_actions"],
    },
}


class AgentIncompleteError(RuntimeError):
    """Raised when the LLM agent exhausts its iteration budget without a verdict."""


def _build_initial_prompt(alert: Alert) -> str:
    lines = [
        "## Alert",
        f"alert_id: {alert.alert_id}",
        f"host: {alert.host or '(none given)'}",
        f"indicators: {', '.join(alert.indicators) if alert.indicators else '(none given)'}",
        "description:",
        alert.description.strip(),
    ]
    return "\n".join(lines)


class LLMAgent:
    """Wraps the Claude tool-calling loop, with a fake-client injection point for tests."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        max_iterations: int = DEFAULT_MAX_ITERATIONS,
        client=None,
    ):
        self.model = model
        self.max_iterations = max_iterations
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

    def investigate(self, alert: Alert) -> InvestigationResult:
        if self._client is None:
            raise RuntimeError("LLMAgent is not live: no API key/client and no 'anthropic' package available.")

        tool_schemas = tools.anthropic_tool_schemas() + [SUBMIT_VERDICT_TOOL]
        messages = [{"role": "user", "content": _build_initial_prompt(alert)}]
        trace: list[ToolCall] = []

        for _ in range(self.max_iterations):
            response = self._client.messages.create(
                model=self.model,
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                tools=tool_schemas,
                messages=messages,
            )
            messages.append({"role": "assistant", "content": response.content})

            tool_use_blocks = [b for b in response.content if getattr(b, "type", None) == "tool_use"]
            if not tool_use_blocks:
                break

            text_blocks = [b.text for b in response.content if getattr(b, "type", None) == "text" and b.text.strip()]
            reasoning = text_blocks[0] if text_blocks else "(no reasoning text provided for this step)"

            tool_results = []
            verdict_input = None
            for block in tool_use_blocks:
                if block.name == "submit_verdict":
                    verdict_input = block.input
                    tool_results.append(
                        {"type": "tool_result", "tool_use_id": block.id, "content": "Verdict recorded."}
                    )
                    continue
                try:
                    output = tools.call_tool(block.name, block.input)
                except Exception as exc:  # pragma: no cover - defensive, bad tool input from the model
                    output = {"error": str(exc)}
                trace.append(ToolCall(tool=block.name, input=block.input, output=output, reasoning=reasoning))
                tool_results.append(
                    {"type": "tool_result", "tool_use_id": block.id, "content": json.dumps(output)}
                )

            if verdict_input is not None:
                return InvestigationResult(
                    alert=alert,
                    trace=trace,
                    risk_score=int(verdict_input["risk_score"]),
                    risk_band=verdict_input["risk_band"],
                    verdict=verdict_input["verdict"],
                    confidence=verdict_input["confidence"],
                    summary=verdict_input["summary"],
                    recommended_actions=list(verdict_input["recommended_actions"]),
                    mode="llm_agent",
                )

            messages.append({"role": "user", "content": tool_results})

        raise AgentIncompleteError(
            f"LLM agent did not reach a verdict within {self.max_iterations} iterations."
        )
