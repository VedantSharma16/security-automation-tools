"""Pluggable narrative summarizers for recon reports.

The structured findings (header grade, TLS findings, fingerprinted tech) are
the source of truth; a summarizer only turns them into prose. This keeps any
LLM call grounded in what the pipeline already verified, rather than asking
the model to re-derive conclusions from raw headers.

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
    "You are an application-security consultant writing the narrative section of an "
    "automated web recon report. You are given ONLY a JSON object of structured "
    "findings already produced by a rule-based pipeline (header grading, TLS "
    "inspection, technology fingerprinting) -- you have no other access to the "
    "target. Do not invent vulnerabilities, versions, or facts not present in the "
    "JSON. Write in three short sections: 'Executive Summary', 'Key Risks' "
    "(prioritized, most severe first), and 'Recommended Remediations'. Be concise "
    "and concrete; prefer specifics from the evidence over generic advice."
)


class Summarizer(Protocol):
    def summarize(self, result: dict) -> str: ...


class TemplateSummarizer:
    """Deterministic, offline narrative built directly from the pipeline's result dict."""

    def summarize(self, result: dict) -> str:
        if result["http"]["error"]:
            return f"The target could not be reached: {result['http']['error']}. No further analysis was possible."

        headers = result["security_headers"]
        lines = [
            f"Security header grade: {headers['grade']} ({headers['score']}/100). "
            f"Overall risk score: {result['risk_score']}/100 ({result['risk_grade']}).",
            "",
        ]

        if headers["findings"]:
            lines.append(f"{len(headers['findings'])} header-level issue(s) found:")
            for f in headers["findings"]:
                lines.append(f"  - [{f['severity']}] {f['message']}")
        else:
            lines.append("No missing security headers or cookie flag issues detected.")

        if result["tls_findings"]:
            lines.append("")
            lines.append(f"{len(result['tls_findings'])} TLS issue(s) found:")
            for f in result["tls_findings"]:
                lines.append(f"  - [{f['severity']}] {f['message']}")

        if result["technologies"]:
            lines.append("")
            names = ", ".join(sorted({t["name"] for t in result["technologies"]}))
            lines.append(f"Fingerprinted technologies: {names}.")

        lines.append("")
        lines.append(
            "Recommended remediations: add the missing security headers listed above, "
            "renew/rotate TLS certificates before expiry, remove version-disclosing "
            "banners, and set Secure/HttpOnly/SameSite on all session cookies."
        )
        return "\n".join(lines)


class AnthropicSummarizer:
    """Sends the structured result (not raw responses) to a Claude model for narrative synthesis."""

    def __init__(self, model: str = "claude-sonnet-5", api_key: str | None = None):
        from anthropic import Anthropic  # imported lazily so it's a true optional dependency

        self._client = Anthropic(api_key=api_key) if api_key else Anthropic()
        self._model = model

    def summarize(self, result: dict) -> str:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=700,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": json.dumps(result, indent=2)}],
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
