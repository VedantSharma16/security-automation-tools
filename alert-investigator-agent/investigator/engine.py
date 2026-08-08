"""Entry point that picks the live LLM agent or the offline planner, with fallback."""

from __future__ import annotations

from investigator import planner
from investigator.llm_agent import LLMAgent
from investigator.state import Alert, InvestigationResult


def investigate(alert: Alert, use_llm: bool = True, agent: LLMAgent | None = None) -> InvestigationResult:
    """Investigate ``alert``, preferring the live LLM agent when available.

    Falls back to the deterministic offline planner if no LLM is configured,
    or if the live agent fails (API error, or it exhausts its iteration
    budget without submitting a verdict) — an agentic loop that can't
    converge should never leave an alert uninvestigated.
    """
    if use_llm:
        llm_agent = agent or LLMAgent()
        if llm_agent.is_live:
            try:
                return llm_agent.investigate(alert)
            except Exception as exc:  # noqa: BLE001 - agent failure/timeout is a safety net, not a crash
                result = planner.run(alert)
                result.summary = f"{result.summary} [LLM agent unavailable, offline planner used: {exc}]"
                return result

    return planner.run(alert)
