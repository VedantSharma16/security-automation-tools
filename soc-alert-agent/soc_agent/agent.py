"""Facade that picks the LLM-backed agent when available, else the deterministic planner."""

from __future__ import annotations

import os

from .models import Alert, AgentResult
from .planner import run_deterministic
from .tools import ToolRegistry


def run_agent(
    alert: Alert,
    tools: ToolRegistry,
    use_llm: bool = False,
    api_key: str | None = None,
    model: str = "claude-sonnet-5",
    max_steps: int = 8,
) -> AgentResult:
    """Triage one alert, returning a full audit trail plus a verdict.

    With ``use_llm=True`` and a usable Anthropic API key, the model drives an
    actual tool-calling loop. Otherwise (no key, package missing, or the API
    call fails) it falls back to the deterministic planner, exactly like the
    other tools in this repo fall back to a template summary offline.
    """
    if use_llm:
        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if key:
            try:
                from .llm_agent import run_llm

                return run_llm(alert, tools, api_key=key, model=model, max_steps=max_steps)
            except ImportError:
                pass
            except Exception as exc:  # pragma: no cover - network/SDK failure path
                result = run_deterministic(alert, tools, max_steps=max_steps)
                result.note = f"LLM agent loop failed, deterministic fallback used: {exc}"
                return result

    return run_deterministic(alert, tools, max_steps=max_steps)
