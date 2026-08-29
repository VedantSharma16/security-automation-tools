"""Pluggable narrative summarizers for the attack-surface report.

Same design as the other tools in this repo: the structured findings are
the source of truth, and a summarizer only turns them into prose. The LLM
never sees live network data -- only the findings the recon modules already
produced -- so the narrative can't invent hosts, headers, or certificates
that weren't actually observed.

TemplateSummarizer is deterministic, dependency-free, and the default.
AnthropicSummarizer is opt-in (`--llm`) and requires the `anthropic`
package plus an API key; `get_summarizer` falls back to the template
summarizer (with an explanatory note) if either is missing.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Protocol

SYSTEM_PROMPT = (
    "You are an external penetration tester writing the narrative section of an "
    "automated attack-surface report. You are given ONLY a JSON object of "
    "structured findings already produced by recon modules (DNS, subdomain "
    "enumeration, HTTP header analysis, TLS inspection) -- you have no other "
    "access to the target. Do not invent hosts, headers, certificates, or facts "
    "not present in the JSON. Write in three short sections: 'Executive Summary', "
    "'Highest-Priority Risks', and 'Recommended Remediations'. Be concise and "
    "concrete; prefer specifics from the evidence over generic advice."
)


class Summarizer(Protocol):
    def summarize(self, report: dict) -> str: ...


class TemplateSummarizer:
    """Deterministic, offline narrative built directly from the report's findings."""

    def summarize(self, report: dict) -> str:
        summary = report["summary"]
        findings = [f for f in report["findings"] if f["severity"] != "INFO"]

        if not findings:
            return (
                f"No actionable security findings were identified for "
                f"{report['domain']}. The discovered configuration appears sound "
                f"based on the checks performed."
            )

        lines = [
            f"{summary['total_findings']} total finding(s) for {report['domain']}, "
            f"highest severity {summary['highest_severity']}, "
            f"risk score {summary['risk_score']}/100.",
            "",
        ]

        by_source: dict[str, list] = {}
        for f in findings:
            by_source.setdefault(f["source"], []).append(f)

        if "tls" in by_source:
            lines.append(f"{len(by_source['tls'])} TLS/certificate issue(s) identified.")
        if "http_headers" in by_source:
            lines.append(
                f"{len(by_source['http_headers'])} HTTP security header issue(s) identified."
            )
        if "dns" in by_source:
            lines.append(f"{len(by_source['dns'])} DNS/email-security issue(s) identified.")
        if "subdomains" in by_source:
            lines.append(f"{len(by_source['subdomains'])} subdomain-exposure issue(s) identified.")

        lines.append("")
        lines.append(
            "Recommended actions: prioritize CRITICAL and HIGH findings first "
            "(expired certificates, deprecated TLS, missing HSTS), then close out "
            "the remaining missing-header and DNS gaps."
        )
        return "\n".join(lines)


class AnthropicSummarizer:
    """Sends the structured report (not live network data) to a Claude model."""

    def __init__(self, model: str = "claude-sonnet-5", api_key: str | None = None):
        from anthropic import Anthropic  # imported lazily so it's a true optional dependency

        self._client = Anthropic(api_key=api_key) if api_key else Anthropic()
        self._model = model

    def summarize(self, report: dict) -> str:
        evidence = {
            "domain": report["domain"],
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
