"""Pluggable narrative summarizers for the phishing triage report.

The structured findings (verdict, score, per-signal reasons) are the source of
truth; a summarizer only turns them into prose. This keeps any LLM call grounded
in evidence the rule-based analyzers already produced, instead of asking the
model to read the raw email and invent conclusions.

`TemplateSummarizer` is deterministic, dependency-free, and always available --
it's the default, and what the test suite and CI run against.
`AnthropicSummarizer` is opt-in (`--llm`) and requires the `anthropic` package
plus an API key; if either is missing, `get_summarizer` falls back to the
template summarizer and explains why on stderr.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Protocol

SYSTEM_PROMPT = (
    "You are a SOC/incident-response analyst writing the narrative section of an "
    "automated phishing triage report. You are given ONLY a JSON object of "
    "structured findings already produced by rule-based analyzers (SPF/DKIM/DMARC "
    "results, suspicious link findings, social-engineering language matches, "
    "sender-impersonation checks, attachment findings, and an overall score/"
    "verdict) -- you have no access to the raw email itself. Do not invent facts, "
    "senders, links, or events that are not present in the JSON. Write in three "
    "short sections: 'Verdict Rationale', 'Likely Objective' (what the attacker "
    "is probably after, or state clearly if the evidence doesn't support one), "
    "and 'Recommended Actions'. Be concise and concrete; prefer specifics from "
    "the evidence over generic advice."
)


class Summarizer(Protocol):
    def summarize(self, report: dict) -> str: ...


class TemplateSummarizer:
    """Deterministic, offline narrative built directly from the report's findings."""

    def summarize(self, report: dict) -> str:
        triage = report["triage"]
        reasons = triage["reasons"]

        if triage["verdict"] == "benign" and not reasons:
            return (
                "No phishing indicators were detected. Authentication checks passed "
                "or were inconclusive, no suspicious links or attachments were found, "
                "and the message body does not contain notable social-engineering "
                "language. No further action is recommended."
            )

        lines = [
            f"Verdict: {triage['verdict'].replace('_', ' ').upper()} "
            f"(score {triage['score']}/100).",
            "",
        ]

        if reasons:
            lines.append("Key indicators:")
            for reason in reasons[:8]:
                lines.append(f"- {reason}")
            lines.append("")

        if triage["verdict"] == "likely_phishing":
            lines.append(
                "Recommended actions: do not click any links or open attachments, "
                "report the message to the security team, block the sending domain "
                "at the mail gateway, and search the mailbox environment for other "
                "copies of this message."
            )
        elif triage["verdict"] == "suspicious":
            lines.append(
                "Recommended actions: do not interact with links or attachments until "
                "an analyst confirms legitimacy directly with the purported sender "
                "through a separate, known-good channel."
            )
        else:
            lines.append(
                "Recommended actions: no action required, but note the flagged "
                "signal(s) above if reviewing this message manually."
            )

        return "\n".join(lines)


class AnthropicSummarizer:
    """Sends the structured report (not the raw email) to a Claude model for narrative synthesis."""

    def __init__(self, model: str = "claude-sonnet-5", api_key: str | None = None):
        from anthropic import Anthropic  # imported lazily so it's a true optional dependency

        self._client = Anthropic(api_key=api_key) if api_key else Anthropic()
        self._model = model

    def summarize(self, report: dict) -> str:
        evidence = {
            "sender": report["sender"],
            "authentication": report["authentication"],
            "url_findings": report["url_findings"],
            "content_findings": report["content_findings"],
            "attachment_findings": report["attachment_findings"],
            "triage": report["triage"],
        }
        response = self._client.messages.create(
            model=self._model,
            max_tokens=700,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": json.dumps(evidence, indent=2)}],
        )
        return "".join(block.text for block in response.content if block.type == "text")


def get_summarizer(use_llm: bool, model: str = "claude-sonnet-5") -> Summarizer:
    """Return an AnthropicSummarizer if requested and usable, else TemplateSummarizer."""
    if not use_llm:
        return TemplateSummarizer()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print(
            "note: --llm requested but ANTHROPIC_API_KEY is not set; "
            "falling back to the offline template summarizer.",
            file=sys.stderr,
        )
        return TemplateSummarizer()

    try:
        return AnthropicSummarizer(model=model, api_key=api_key)
    except ImportError:
        print(
            "note: --llm requested but the 'anthropic' package is not installed; "
            "falling back to the offline template summarizer.",
            file=sys.stderr,
        )
        return TemplateSummarizer()
