"""Pluggable narrative generators for the pentest report.

Mirrors the pattern used by the other tools in this repo: the report's
structured findings (host, port, CVE, CVSS, confidence) are the source of
truth, and a narrator only turns them into prose. TemplateNarrator is
deterministic, dependency-free, and the default used by tests and CI.
AnthropicNarrator is opt-in (`--llm`) and requires the `anthropic` package
plus an API key; get_narrator falls back to the template narrator (with a
stderr note) if either is missing.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Protocol

SYSTEM_PROMPT = (
    "You are a penetration tester writing the narrative section of an automated "
    "attack-surface report. You are given ONLY a JSON object of structured "
    "findings already produced by a CVE-correlation engine -- you have no access "
    "to the raw scan or any other source. Do not invent hosts, services, or CVEs "
    "that are not present in the JSON. Write in three short sections: "
    "'Executive Summary', 'Likely Attack Path' (chain findings into a plausible "
    "path if the evidence supports it, and say clearly if it doesn't), and "
    "'Recommended Remediation' (prioritized, most critical first). Be concise "
    "and concrete; prefer specifics from the evidence over generic advice."
)


class Narrator(Protocol):
    def narrate(self, report: dict) -> str: ...


class TemplateNarrator:
    """Deterministic, offline narrative built directly from the report's findings."""

    def narrate(self, report: dict) -> str:
        summary = report["summary"]
        findings = report["findings"]

        if not findings:
            return (
                "No known CVE or insecure-protocol matches were found against the local "
                "rule database. No further action is recommended from this scan alone."
            )

        lines = [
            f"{summary['total_findings']} finding(s) across {summary['hosts_at_risk']} "
            f"host(s), overall risk {summary['overall_severity'].upper()} "
            f"({summary['overall_score']}/100).",
            "",
        ]

        critical_or_high = [f for f in findings if f["severity"] in ("critical", "high")]
        if critical_or_high:
            top = critical_or_high[0]
            lines.append(
                f"Highest-priority exposure: {top['title']} on {top['host']}:{top['port']} "
                f"({top['rule_id']}, CVSS {top['cvss']})"
                + (", with a known public exploit." if top["exploit_available"] else ".")
            )

        exploitable = [f for f in findings if f["exploit_available"]]
        if exploitable:
            lines.append(
                f"{len(exploitable)} finding(s) have known public exploits and should be "
                "prioritized for remediation or compensating controls before anything else."
            )

        unconfirmed = [f for f in findings if f["confidence"] == "unconfirmed"]
        if unconfirmed:
            lines.append(
                f"{len(unconfirmed)} finding(s) are unconfirmed (product matched but version "
                "could not be verified from the scan) and should be manually validated."
            )

        lines.append("")
        top_host = report["host_risk_ranking"][0]
        lines.append(
            f"Recommended focus: {top_host['host']} "
            f"({top_host['hostname'] or 'no hostname'}), the highest-scoring host at "
            f"{top_host['score']}/100 across {top_host['finding_count']} finding(s)."
        )
        return "\n".join(lines)


class AnthropicNarrator:
    """Sends the structured report (not the raw scan) to a Claude model for narrative synthesis."""

    def __init__(self, model: str = "claude-sonnet-5", api_key: str | None = None):
        from anthropic import Anthropic  # imported lazily so it's a true optional dependency

        self._client = Anthropic(api_key=api_key) if api_key else Anthropic()
        self._model = model

    def narrate(self, report: dict) -> str:
        evidence = {
            "summary": report["summary"],
            "host_risk_ranking": report["host_risk_ranking"],
            "findings": report["findings"],
        }
        response = self._client.messages.create(
            model=self._model,
            max_tokens=700,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": json.dumps(evidence, indent=2)}],
        )
        return "".join(block.text for block in response.content if block.type == "text")


def get_narrator(use_llm: bool, model: str = "claude-sonnet-5") -> Narrator:
    """Return an AnthropicNarrator if requested and usable, else TemplateNarrator."""
    if not use_llm:
        return TemplateNarrator()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print(
            "note: --llm requested but ANTHROPIC_API_KEY is not set; "
            "falling back to the offline template narrator.",
            file=sys.stderr,
        )
        return TemplateNarrator()

    try:
        return AnthropicNarrator(model=model, api_key=api_key)
    except ImportError:
        print(
            "note: --llm requested but the 'anthropic' package is not installed; "
            "falling back to the offline template narrator.",
            file=sys.stderr,
        )
        return TemplateNarrator()
