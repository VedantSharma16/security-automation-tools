"""Pluggable narrative summarizers for phishing triage reports.

The report's structured findings (severity, evidence) are the source of
truth; a summarizer only turns them into prose for a human reader. This
keeps any LLM call grounded in evidence the heuristics already verified,
rather than asking the model to read the raw email and invent conclusions.

TemplateSummarizer is deterministic, dependency-free, and always available
-- it's the default, and what tests and CI run against. AnthropicSummarizer
is opt-in (`--llm`) and requires the `anthropic` package plus an API key; if
either is missing, `get_summarizer` falls back to the template summarizer
and prints a note explaining why.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Protocol

SYSTEM_PROMPT = (
    "You are a SOC analyst writing the narrative section of an automated "
    "phishing triage report. You are given ONLY a JSON object of structured "
    "findings already produced by rule-based heuristics -- you have no access "
    "to the raw email or any other source. Do not invent facts, domains, or "
    "senders that are not present in the JSON. Write in three short sections: "
    "'Executive Summary', 'Why This Looks Suspicious (or Doesn't)', and "
    "'Recommended Actions'. Be concise and concrete; prefer specifics from the "
    "evidence over generic advice."
)


class Summarizer(Protocol):
    def summarize(self, report: dict) -> str: ...


class TemplateSummarizer:
    """Deterministic, offline narrative built directly from the report's summary stats."""

    def summarize(self, report: dict) -> str:
        summary = report["summary"]
        findings = report["findings"]

        if not findings:
            return (
                "No phishing indicators were detected for this message. No further "
                "action is recommended, though standard caution with unsolicited "
                "attachments and links always applies."
            )

        lines = [
            f"{summary['total_findings']} finding(s) detected, "
            f"highest severity {summary['highest_severity']}, "
            f"risk score {summary['risk_score']}/100 "
            f"-> verdict: {summary['verdict'].replace('_', ' ')}.",
            "",
        ]

        by_type = {f["type"] for f in findings}

        if "auth_failure" in by_type:
            lines.append("Sender authentication (SPF/DKIM/DMARC) failed, undermining the claimed sender identity.")
        if "brand_display_name_mismatch" in by_type or "lookalike_sender_domain" in by_type:
            lines.append("The message appears to impersonate a known brand via display name or a typosquatted sending domain.")
        if "mismatched_anchor_text" in by_type or "ip_literal_link" in by_type or "url_shortener" in by_type:
            lines.append("Links in the message are disguised, shortened, or point to a raw IP -- do not click before verifying the true destination.")
        if "dangerous_attachment" in by_type:
            lines.append("An attachment carries an executable or macro-capable extension and should not be opened.")
        if "urgency_language" in by_type:
            lines.append("The message uses urgency/pressure language typical of social engineering.")

        lines.append("")
        lines.append(
            "Recommended actions: do not click any links or open attachments, report the "
            "message to the security team, and if credentials were entered on a linked "
            "page, rotate them immediately."
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
            "subject": report["subject"],
            "link_count": report["link_count"],
            "attachment_count": report["attachment_count"],
            "summary": report["summary"],
            "findings": report["findings"],
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
