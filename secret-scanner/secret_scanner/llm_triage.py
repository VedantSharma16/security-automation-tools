"""Pluggable triage narrative for a scan report.

Only redacted, structured findings (severity, rule id, file/line, entropy --
never the actual secret value) are ever handed to a summarizer, LLM or not.
TemplateSummarizer is deterministic, dependency-free, and always available;
it's the default and what tests/CI run against. AnthropicSummarizer is
opt-in (`--llm`) and requires the `anthropic` package plus an API key; if
either is missing, `get_summarizer` falls back to the template summarizer.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Protocol

SYSTEM_PROMPT = (
    "You are an application-security engineer writing the triage section of an "
    "automated secret-scan report. You are given ONLY a JSON object of "
    "structured, already-redacted findings -- you never see actual secret "
    "values and have no other source of information. Do not invent files, "
    "commits, or credential values not present in the JSON. Write two short "
    "sections: 'Triage Summary' (what kinds of secrets were found and where, "
    "prioritized by severity) and 'Remediation Steps' (concrete: rotate the "
    "affected credential, purge it from git history, add prevention such as a "
    "pre-commit hook). Be concise and concrete."
)


class Summarizer(Protocol):
    def summarize(self, report: dict) -> str: ...


class TemplateSummarizer:
    """Deterministic, offline triage narrative built from the report's findings."""

    def summarize(self, report: dict) -> str:
        summary = report["summary"]
        findings = report["findings"]

        if not findings:
            return "No secrets detected. No remediation required."

        lines = [
            f"{summary['total_findings']} finding(s) detected "
            f"({summary['working_tree_findings']} in the working tree, "
            f"{summary['git_history_findings']} in git history), "
            f"highest severity {summary['highest_severity']}, "
            f"risk score {summary['risk_score']}/100.",
            "",
        ]

        by_rule: dict = {}
        for f in findings:
            by_rule.setdefault(f["rule_id"], []).append(f)

        for rule_id, matches in sorted(by_rule.items(), key=lambda kv: kv[0]):
            locations = ", ".join(f"{m['file_path']}:{m['line_number']}" for m in matches[:3])
            more = f" (+{len(matches) - 3} more)" if len(matches) > 3 else ""
            lines.append(f"- {rule_id} x{len(matches)}: {locations}{more}")

        if summary["git_history_findings"]:
            lines.append("")
            lines.append(
                "Findings present only in git history are still exposed to anyone with "
                "clone access; removing them from the working tree alone is not sufficient."
            )

        lines.append("")
        lines.append(
            "Recommended actions: rotate every credential flagged above, purge secrets "
            "found in git history (e.g. with `git filter-repo` or BFG), and add this "
            "scanner as a pre-commit hook / CI gate to prevent recurrence."
        )
        return "\n".join(lines)


class AnthropicSummarizer:
    """Sends the structured, redacted report (never raw secret values) to a Claude model."""

    def __init__(self, model: str = "claude-sonnet-5", api_key: str | None = None):
        from anthropic import Anthropic  # imported lazily so it's a true optional dependency

        self._client = Anthropic(api_key=api_key) if api_key else Anthropic()
        self._model = model

    def summarize(self, report: dict) -> str:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=700,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": json.dumps(report, indent=2)}],
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
