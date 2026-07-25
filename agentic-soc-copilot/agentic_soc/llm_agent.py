"""Live agentic loop using Anthropic's native tool-use (function-calling) API.

This is the genuinely *agentic* half of the project: rather than one prompt
producing one text response, the model is handed a set of tools and decides
for itself which to call and in what order, observing each tool's result
before deciding its next move (a ReAct-style loop). The loop terminates when
the model calls the ``submit_verdict`` tool, which forces a structured,
schema-validated final answer instead of free-text that would need fragile
parsing.

A ``client`` can be injected directly for testing so the tool-calling loop
itself is unit-testable without any network access or the ``anthropic``
package installed -- see ``tests/test_llm_agent.py``.
"""

from __future__ import annotations

import json
import os

from agentic_soc.tools import ToolRegistry
from agentic_soc.transcript import AgentStep, AgentTranscript, Verdict

DEFAULT_MODEL = "claude-sonnet-5"
DEFAULT_MAX_STEPS = 6

SYSTEM_PROMPT = (
    "You are an autonomous SOC tier-2 triage agent investigating a single security alert. "
    "You have tools to check indicators against local threat intel, check process reputation "
    "against known LOLBins, look up relevant MITRE ATT&CK techniques, and check the business "
    "criticality of the affected asset. Call tools to gather evidence before concluding -- do "
    "not guess. Once you have enough evidence, call submit_verdict exactly once with your final "
    "verdict, a confidence between 0 and 1, your reasoning, and concrete recommended actions."
)

SUBMIT_VERDICT_TOOL = {
    "name": "submit_verdict",
    "description": "Submit the final triage verdict and end the investigation. Call this exactly once, as the last action.",
    "input_schema": {
        "type": "object",
        "properties": {
            "verdict": {"type": "string", "enum": ["malicious", "suspicious", "benign"]},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "reasoning": {"type": "string", "description": "Why you reached this verdict, grounded in the tool observations."},
            "recommended_actions": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["verdict", "confidence", "reasoning", "recommended_actions"],
    },
}

_BUDGET_EXHAUSTED_ACTIONS = [
    "Escalate to a human analyst.",
    "Review the tool observations gathered so far before deciding.",
]


def _extract_text(content_blocks) -> str:
    return " ".join(b.text for b in content_blocks if getattr(b, "type", "") == "text").strip()


class LLMAgent:
    """Runs the live tool-calling investigation loop against Claude."""

    def __init__(
        self,
        registry: ToolRegistry | None = None,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        max_steps: int = DEFAULT_MAX_STEPS,
        client=None,
    ):
        self.registry = registry or ToolRegistry.from_files()
        self.model = model
        self.max_steps = max_steps
        self._client = client
        if self._client is None:
            key = api_key or os.environ.get("ANTHROPIC_API_KEY")
            if key:
                try:
                    import anthropic  # type: ignore

                    self._client = anthropic.Anthropic(api_key=key)
                except ImportError:
                    self._client = None

    @property
    def is_live(self) -> bool:
        return self._client is not None

    def investigate(self, alert_text: str) -> AgentTranscript:
        if self._client is None:
            raise RuntimeError("LLMAgent has no client configured; check is_live before calling investigate().")

        tools = self.registry.tools()
        tool_map = {t.name: t for t in tools}
        tool_schemas = [t.anthropic_schema() for t in tools] + [SUBMIT_VERDICT_TOOL]

        messages = [{"role": "user", "content": f"Investigate this alert:\n\n{alert_text}"}]
        steps: list[AgentStep] = []

        for _ in range(self.max_steps):
            response = self._client.messages.create(
                model=self.model,
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                tools=tool_schemas,
                messages=messages,
            )
            messages.append({"role": "assistant", "content": response.content})

            tool_use_blocks = [b for b in response.content if getattr(b, "type", "") == "tool_use"]
            if not tool_use_blocks:
                break

            thought = _extract_text(response.content)
            tool_results_content = []
            verdict = None

            for block in tool_use_blocks:
                if block.name == "submit_verdict":
                    verdict = Verdict(**block.input)
                    tool_results_content.append(
                        {"type": "tool_result", "tool_use_id": block.id, "content": "Verdict recorded."}
                    )
                    continue

                tool = tool_map.get(block.name)
                observation = (
                    {"error": f"unknown tool {block.name}"} if tool is None else tool.run(block.input).data
                )
                steps.append(
                    AgentStep(thought=thought, tool=block.name, tool_input=dict(block.input), observation=observation)
                )
                tool_results_content.append(
                    {"type": "tool_result", "tool_use_id": block.id, "content": json.dumps(observation)}
                )

            messages.append({"role": "user", "content": tool_results_content})

            if verdict is not None:
                return AgentTranscript(alert_text=alert_text, steps=steps, verdict=verdict, llm_backed=True)

        fallback_verdict = Verdict(
            verdict="suspicious",
            confidence=0.3,
            reasoning=(
                "The agent did not call submit_verdict within the available steps "
                "(step budget exhausted or the model stopped without concluding). "
                "Failing safe to 'suspicious' rather than guessing."
            ),
            recommended_actions=_BUDGET_EXHAUSTED_ACTIONS,
        )
        return AgentTranscript(alert_text=alert_text, steps=steps, verdict=fallback_verdict, llm_backed=True)
