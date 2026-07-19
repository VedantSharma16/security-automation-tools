"""LLM-backed narrative summarization, with a deterministic offline fallback.

Live mode calls the Claude API (via the official ``anthropic`` SDK) when
``ANTHROPIC_API_KEY`` is set and the package is installed. Without a key,
:meth:`LLMClient.summarize` falls back to a template-driven summary built
directly from the structured triage context, so the tool is fully
runnable — and testable — offline.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

DEFAULT_MODEL = "claude-sonnet-5"

SYSTEM_PROMPT = (
    "You are a SOC tier-2 analyst assistant. Given extracted indicators, "
    "local threat-intel enrichment, and retrieved MITRE ATT&CK technique "
    "context for a security alert, write a concise triage summary: what "
    "likely happened, why it matters, and 2-4 concrete next steps for the "
    "on-call analyst. Be direct and avoid hedging language when the "
    "evidence is clear."
)


@dataclass
class TriageContext:
    alert_text: str
    indicators: list[dict]
    enrichment: list[dict]
    matched_techniques: list[tuple[dict, float]]
    severity: str


def build_prompt(context: TriageContext) -> str:
    lines = [
        "## Alert",
        context.alert_text.strip(),
        "",
        "## Extracted indicators",
    ]
    if context.indicators:
        for ioc in context.indicators:
            lines.append(f"- [{ioc['category']}] {ioc['value']}")
    else:
        lines.append("- (none found)")

    lines += ["", "## Threat-intel enrichment"]
    flagged = [e for e in context.enrichment if e["is_known_malicious"]]
    if flagged:
        for hit in flagged:
            lines.append(
                f"- {hit['value']} ({hit['category']}) — KNOWN MALICIOUS, "
                f"confidence={hit['confidence']}, source={hit['source']}: {hit['notes']}"
            )
    else:
        lines.append("- No indicators matched the local threat-intel feed.")

    lines += ["", "## Retrieved ATT&CK context (RAG)"]
    if context.matched_techniques:
        for technique, score in context.matched_techniques:
            lines.append(
                f"- {technique['id']} {technique['name']} ({technique['tactic']}) "
                f"[relevance={score:.2f}]: {technique['text']}"
            )
    else:
        lines.append("- No closely matching techniques retrieved.")

    lines += ["", f"## Heuristic severity: {context.severity}"]
    return "\n".join(lines)


class LLMClient:
    """Wraps Anthropic API access with a safe offline fallback."""

    def __init__(self, api_key: str | None = None, model: str = DEFAULT_MODEL):
        self.model = model
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

    def summarize(self, context: TriageContext) -> str:
        prompt = build_prompt(context)
        if self._client is not None:
            try:
                response = self._client.messages.create(
                    model=self.model,
                    max_tokens=600,
                    system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": prompt}],
                )
                return "".join(
                    block.text for block in response.content if getattr(block, "type", "") == "text"
                ).strip()
            except Exception as exc:  # pragma: no cover - network/SDK failure path
                return self._offline_summary(context) + f"\n\n[LLM call failed, offline fallback used: {exc}]"
        return self._offline_summary(context)

    @staticmethod
    def _offline_summary(context: TriageContext) -> str:
        flagged = [e for e in context.enrichment if e["is_known_malicious"]]
        top_technique = context.matched_techniques[0][0] if context.matched_techniques else None

        parts = [
            "[offline heuristic summary — set ANTHROPIC_API_KEY for LLM-generated analysis]",
            f"Severity: {context.severity.upper()}.",
        ]

        if flagged:
            names = ", ".join(f"{e['value']} ({e['category']})" for e in flagged)
            parts.append(f"Known-malicious indicators observed: {names}.")
        else:
            parts.append("No indicators matched the local threat-intel feed.")

        if top_technique:
            parts.append(
                f"Alert language most closely resembles ATT&CK technique "
                f"{top_technique['id']} ({top_technique['name']}, tactic: {top_technique['tactic']})."
            )

        parts.append(
            "Recommended next steps: isolate affected host(s) if severity is high or "
            "critical, pivot on the flagged indicators in EDR/SIEM for related activity, "
            "and confirm whether the matched ATT&CK technique aligns with the raw log evidence "
            "before closing or escalating the alert."
        )
        return " ".join(parts)
