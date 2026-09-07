"""Pluggable narrative summarizers for recon reports.

Same grounding pattern used elsewhere in this repo: the structured findings
are the source of truth, and a summarizer only turns them into prose. The
model is given the JSON report and nothing else, so it cannot invent hosts,
ports, or CVEs that the deterministic checks didn't actually observe.

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
    "You are a penetration tester writing the findings narrative for a "
    "network reconnaissance report from an authorized engagement. You are "
    "given ONLY a JSON object of structured findings already produced by "
    "deterministic port-scan and HTTP header checks -- you have no other "
    "access and must not invent hosts, ports, services, or CVEs that are not "
    "present in the JSON. Write three short sections: 'Executive Summary', "
    "'Attack Surface Assessment', and 'Prioritized Remediation' (ordered by "
    "severity). Be concise and concrete."
)


class Summarizer(Protocol):
    def summarize(self, report: dict) -> str: ...


class TemplateSummarizer:
    """Deterministic, offline narrative built directly from the report's findings."""

    def summarize(self, report: dict) -> str:
        summary = report["summary"]
        findings = report["findings"]

        if not findings:
            return (
                f"{summary['open_port_count']} open port(s) found on "
                f"{report['target']}, no risk findings triggered by the "
                "current rule set. No further action recommended beyond "
                "periodic re-scanning."
            )

        lines = [
            f"{summary['total_findings']} finding(s) across "
            f"{summary['open_port_count']} open port(s), highest severity "
            f"{summary['highest_severity'].upper()}, risk score "
            f"{summary['risk_score']}/100.",
            "",
        ]

        by_type: dict[str, list[dict]] = {}
        for f in findings:
            by_type.setdefault(f["type"], []).append(f)

        if "exposed_database" in by_type:
            ports = ", ".join(f"port {f['port']}" for f in by_type["exposed_database"])
            lines.append(f"Database service(s) directly reachable: {ports}.")
        if "cleartext_protocol" in by_type:
            ports = ", ".join(f"port {f['port']}" for f in by_type["cleartext_protocol"])
            lines.append(f"Cleartext protocol(s) in use: {ports}.")
        if "exposed_admin_surface" in by_type:
            ports = ", ".join(f"port {f['port']}" for f in by_type["exposed_admin_surface"])
            lines.append(f"Remote-admin surface(s) exposed: {ports}.")
        if "missing_transport_security" in by_type or "missing_header" in by_type:
            lines.append(
                "One or more web endpoints are missing recommended security "
                "headers or transport encryption."
            )

        lines += [
            "",
            "Recommended priority: address CRITICAL/HIGH findings first "
            "(exposed databases and admin surfaces), then cleartext "
            "protocols, then web-header hardening.",
        ]
        return "\n".join(lines)


class AnthropicSummarizer:
    """Sends the structured report (not raw scan traffic) to a Claude model."""

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
