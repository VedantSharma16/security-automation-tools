"""LLM-assisted alert triage, grounded with retrieved ATT&CK context.

The triage engine is deliberately decoupled from any specific LLM provider
via the LLMClient protocol, so it can be tested without network access and
swapped between providers without touching detection or prompt logic.
"""

from __future__ import annotations

import os
from typing import Protocol

from .knowledge_base import KnowledgeBase
from .models import Alert


class LLMClient(Protocol):
    def complete(self, system: str, prompt: str) -> str: ...


class AnthropicClient:
    """Thin wrapper around the Anthropic Messages API.

    The `anthropic` package is imported lazily so it's only a hard
    dependency for callers who actually want live LLM triage.
    """

    def __init__(self, model: str = "claude-sonnet-5", api_key: str | None = None):
        import anthropic  # noqa: PLC0415 - intentionally lazy/optional import

        resolved_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not resolved_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set and no api_key was provided")
        self._client = anthropic.Anthropic(api_key=resolved_key)
        self.model = model

    def complete(self, system: str, prompt: str) -> str:
        response = self._client.messages.create(
            model=self.model,
            max_tokens=500,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(block.text for block in response.content if block.type == "text")


class AlertTriageEngine:
    """Builds an ATT&CK-grounded prompt for an alert and triages it, either
    via a real LLM client or a deterministic offline fallback.
    """

    SYSTEM_PROMPT = (
        "You are a SOC analyst assistant. Given a detection alert and relevant "
        "MITRE ATT&CK context, produce a concise triage covering: likely intent, "
        "false-positive likelihood, and a recommended next action. "
        "Respond in under 120 words."
    )

    def __init__(self, kb: KnowledgeBase, llm_client: LLMClient | None = None):
        self.kb = kb
        self.llm_client = llm_client

    def build_prompt(self, alert: Alert) -> tuple[str, str]:
        context_entries = self.kb.retrieve(f"{alert.description} {' '.join(alert.tags)}")
        context = "\n".join(
            f"- {entry['technique_id']} {entry['name']}: {entry['description']}"
            for entry in context_entries
        )
        prompt = (
            f"Alert: {alert.title} (severity={alert.severity.value})\n"
            f"Rule ID: {alert.rule_id}\n"
            f"Description: {alert.description}\n"
            f"Affected user(s): {', '.join(alert.users) or 'unknown'}\n"
            f"Source IP(s): {', '.join(alert.source_ips) or 'unknown'}\n"
            f"Event count: {len(alert.events)}\n\n"
            f"Relevant ATT&CK techniques:\n{context or '(none matched)'}"
        )
        return self.SYSTEM_PROMPT, prompt

    def triage(self, alert: Alert) -> str:
        if self.llm_client is None:
            return self._heuristic_summary(alert)
        system, prompt = self.build_prompt(alert)
        return self.llm_client.complete(system, prompt)

    def _heuristic_summary(self, alert: Alert) -> str:
        return (
            f"[offline triage] {alert.title} — severity {alert.severity.value}. "
            f"{len(alert.events)} event(s) from {', '.join(alert.source_ips) or 'an unknown IP'} "
            f"targeting user(s) {', '.join(alert.users) or 'unknown'}. "
            "Recommend reviewing source IP reputation and confirming activity with the account owner."
        )
