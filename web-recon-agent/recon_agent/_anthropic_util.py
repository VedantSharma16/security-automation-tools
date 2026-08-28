"""Shared helper for the two places this package optionally talks to Claude:
the dynamic LLM planner (``planner.LLMPlanner``) and the report narrator
(``llm_client.Narrator``). Both need the exact same "do we have a usable key
and SDK" check, so it lives here once.
"""

from __future__ import annotations

import os

DEFAULT_MODEL = "claude-sonnet-5"


def get_client(api_key: str | None = None):
    """Return an ``anthropic.Anthropic`` client, or ``None`` if unavailable.

    Callers must always have a deterministic fallback for the ``None`` case —
    every LLM-backed feature in this project works fully offline.
    """
    resolved_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not resolved_key:
        return None
    try:
        import anthropic  # type: ignore

        return anthropic.Anthropic(api_key=resolved_key)
    except ImportError:
        return None
