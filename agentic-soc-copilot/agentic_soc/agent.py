"""Facade that picks the live tool-calling agent when available, and falls
back to the deterministic offline planner otherwise -- the same
graceful-degradation pattern used by ``LLMClient`` in ``ioc-triage-assistant``
and ``LLMSummarizer`` in ``log-triage-assistant``, applied to a full agent
loop instead of a single summarization call.
"""

from __future__ import annotations

from agentic_soc.llm_agent import LLMAgent
from agentic_soc.offline_agent import OfflineAgent
from agentic_soc.tools import ToolRegistry
from agentic_soc.transcript import AgentTranscript


class SocAgent:
    def __init__(
        self,
        registry: ToolRegistry | None = None,
        api_key: str | None = None,
        model: str | None = None,
        max_steps: int = 6,
    ):
        self.registry = registry or ToolRegistry.from_files()
        llm_kwargs = {"model": model} if model else {}
        self._llm_agent = LLMAgent(self.registry, api_key=api_key, max_steps=max_steps, **llm_kwargs)
        self._offline_agent = OfflineAgent(self.registry)

    @property
    def is_live(self) -> bool:
        return self._llm_agent.is_live

    def investigate(self, alert_text: str) -> AgentTranscript:
        if self._llm_agent.is_live:
            try:
                return self._llm_agent.investigate(alert_text)
            except Exception as exc:  # pragma: no cover - network/SDK failure path
                transcript = self._offline_agent.investigate(alert_text)
                transcript.verdict.reasoning += (
                    f" [Live LLM agent call failed, offline deterministic planner used instead: {exc}]"
                )
                return transcript
        return self._offline_agent.investigate(alert_text)
