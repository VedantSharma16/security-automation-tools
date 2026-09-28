"""Pluggable narrative summarizers for phishing triage reports.

The report's structured findings (severity, evidence, ATT&CK mapping) are the
source of truth; a summarizer only turns them into prose for a human analyst.
This keeps any LLM call grounded in evidence the detectors already verified,
rather than asking the model to read the raw email and invent conclusions.

TemplateSummarizer is deterministic, dependency-free, and always available --
it's the default, and what tests and CI run against. AnthropicSummarizer is
opt-in (`--llm`) and requires the `anthropic` package plus an API key; if
either is missing, `get_summarizer` falls back to the template summarizer and
prints a note explaining why.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Protocol

SYSTEM_PROMPT = (
    "You are a SOC analyst writing the narrative section of an automated phishing "
    "triage report. You are given ONLY a JSON object of structured findings already "
    "produced by rule-based detectors -- you have no access to the raw email or any "
    "other source. Do not invent facts, domains, or details that are not present in "
    "the JSON. Write in three short sections: 'Executive Summary', 'Likely Intent' "
    "(what the attacker is probably after: credentials, malware execution, wire "
    "fraud, etc. -- state clearly if evidence is insufficient), and 'Recommended "
    "Actions'. Be concise and concrete; prefer specifics from the evidence over "
    "generic advice."
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
                "No phishing indicators were detected in this message. "
                "No further action is recommended."
            )

        lines = [
            f"Verdict: {summary['verdict'].upper()} -- {summary['total_findings']} finding(s), "
            f"highest severity {summary['highest_severity']}, risk score {summary['risk_score']}/100.",
            "",
        ]

        by_type = {f["type"] for f in findings}

        if "display_name_spoof" in by_type or "auth_failure" in by_type:
            lines.append(
                "The sender's identity appears to be spoofed or fails authentication checks, "
                "so this message likely did not originate from who it claims to be from."
            )
        if "dangerous_attachment" in by_type:
            lines.append(
                "A high-risk attachment is present; if opened it could lead to code execution "
                "on the recipient's endpoint."
            )
        if "suspicious_url" in by_type or "link_text_mismatch" in by_type:
            lines.append(
                "Links in this message use obfuscation or brand-impersonation techniques "
                "consistent with a credential-harvesting page."
            )
        if "urgency_language" in by_type:
            lines.append(
                "The message uses urgency/pressure language typical of social-engineering lures."
            )

        lines.append("")
        lines.append(
            "Recommended actions: do not click any links or open attachments, report the "
            "message to the security team, and if any user already interacted with it, "
            "reset that user's credentials and check for related activity."
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
            "message": report["message"],
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
