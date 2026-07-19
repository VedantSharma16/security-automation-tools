"""Pluggable narrative summarizers for incident reports.

The report's structured findings (severity, evidence, timestamps) are the
source of truth; a summarizer only turns them into prose for a human reader.
This keeps any LLM call grounded in evidence the detectors already verified,
rather than asking the model to read raw logs and invent conclusions.

TemplateSummarizer is deterministic, dependency-free, and always available —
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
    "You are a SOC/incident-response analyst writing the narrative section of an "
    "automated triage report. You are given ONLY a JSON object of structured "
    "findings already produced by rule-based detectors -- you have no access to "
    "raw logs or any other source. Do not invent facts, IPs, usernames, or events "
    "that are not present in the JSON. Write in three short sections: "
    "'Executive Summary', 'Likely Attack Narrative' (state clearly if evidence is "
    "insufficient to construct one), and 'Recommended Actions'. Be concise and "
    "concrete; prefer specifics from the evidence over generic advice."
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
                "No security-relevant patterns were detected in the analyzed log. "
                "No further action is recommended."
            )

        lines = [
            f"{summary['total_findings']} finding(s) detected, "
            f"highest severity {summary['highest_severity']}, "
            f"risk score {summary['risk_score']}/100.",
            "",
        ]

        by_type = {}
        for f in findings:
            by_type.setdefault(f["type"], []).append(f)

        if "compromise_after_brute_force" in by_type or "brute_force" in by_type:
            lines.append(
                "Evidence indicates a brute-force credential attack, "
                + (
                    "which appears to have succeeded."
                    if "compromise_after_brute_force" in by_type
                    else "with no confirmed successful login."
                )
            )
        if "privilege_escalation" in by_type:
            n = len(by_type["privilege_escalation"])
            lines.append(f"{n} root privilege escalation event(s) observed via sudo.")
        if "persistence_root_account" in by_type or "persistence_crontab" in by_type:
            lines.append(
                "Possible persistence mechanisms detected (root-equivalent account "
                "creation and/or crontab modification)."
            )

        lines.append("")
        lines.append(
            "Recommended actions: rotate credentials for affected accounts, review "
            "and remove unauthorized accounts/cron entries, and inspect the source "
            "IP(s) named in the evidence against threat intelligence feeds."
        )
        return "\n".join(lines)


class AnthropicSummarizer:
    """Sends the structured report (not raw logs) to a Claude model for narrative synthesis."""

    def __init__(self, model: str = "claude-sonnet-5", api_key: str | None = None):
        from anthropic import Anthropic  # imported lazily so it's a true optional dependency

        self._client = Anthropic(api_key=api_key) if api_key else Anthropic()
        self._model = model

    def summarize(self, report: dict) -> str:
        evidence = {
            "summary": report["summary"],
            "findings": report["findings"],
            "event_count": report["event_count"],
            "time_range": report["time_range"],
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
