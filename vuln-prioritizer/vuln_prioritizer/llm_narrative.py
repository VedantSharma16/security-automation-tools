"""Pluggable executive-narrative generators for the remediation report.

The scored findings (priority score, tier, and the rationale that produced
it) are the source of truth; a narrator only turns them into prose for a
non-technical stakeholder. TemplateNarrator is deterministic, dependency-
free, and what tests/CI run against. AnthropicNarrator is opt-in (`--llm`)
and is given ONLY the structured summary + top findings JSON — never asked
to re-derive severity from raw CVE text — so it can't invent a priority
that contradicts the scoring model.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Protocol

SYSTEM_PROMPT = (
    "You are a vulnerability management analyst writing the executive summary "
    "section of an automated patch-prioritization report for a non-technical "
    "stakeholder (e.g. a CISO or engineering director). You are given ONLY a "
    "JSON object containing summary statistics and the highest-priority "
    "findings, each already scored and tiered by a deterministic model that "
    "combines CVSS, EPSS (exploit prediction), CISA KEV (confirmed active "
    "exploitation) status, and asset business-criticality. Do not re-derive "
    "or contradict the given priority tiers or scores, and do not invent "
    "CVEs, hosts, or facts not present in the JSON. Write three short "
    "sections: 'Executive Summary' (2-3 sentences on overall risk posture), "
    "'Top Priorities' (the specific findings that need action first and "
    "why), and 'Recommended Actions' (concrete next steps, e.g. patch "
    "windows, compensating controls for internet-facing assets). Be concise "
    "and concrete."
)


class Narrator(Protocol):
    def narrate(self, report: dict) -> str: ...


class TemplateNarrator:
    """Deterministic, offline narrative built directly from the report's summary stats."""

    def narrate(self, report: dict) -> str:
        summary = report["summary"]
        findings = report["findings"]

        if not findings:
            return "No vulnerabilities were found in the scan input. No remediation action is required."

        lines = [
            f"{summary['total_findings']} finding(s) across {summary['hosts_affected']} host(s), "
            f"average priority score {summary['average_priority_score']}/100.",
            "",
        ]

        p1 = summary["by_tier"].get("P1", 0)
        p2 = summary["by_tier"].get("P2", 0)
        if p1:
            lines.append(f"{p1} finding(s) are P1 (Emergency) and warrant immediate remediation.")
        if p2:
            lines.append(f"{p2} finding(s) are P2 (High) and should be remediated within the standard SLA.")
        if summary["kev_findings"]:
            lines.append(
                f"{summary['kev_findings']} finding(s) are listed in CISA's Known Exploited "
                "Vulnerabilities catalog, meaning exploitation is confirmed and ongoing, not theoretical."
            )

        top = findings[0]
        f = top["finding"]
        lines.append("")
        lines.append(
            f"Highest priority: {f['title']} ({f['cve_id'] or 'no CVE'}) on {f['host']} "
            f"— {top['priority_tier']}, score {top['priority_score']}/100."
        )

        lines.append("")
        lines.append(
            "Recommended actions: patch or apply compensating controls for all P1/P2 findings "
            "first, prioritize internet-facing and business-critical assets within each tier, "
            "and validate CISA KEV-listed CVEs against active exploitation telemetry before "
            "closing them out."
        )
        return "\n".join(lines)


class AnthropicNarrator:
    """Sends the structured summary + top findings (not raw scan data) to Claude."""

    def __init__(self, model: str = "claude-sonnet-5", api_key: str | None = None, top_n: int = 10):
        from anthropic import Anthropic  # imported lazily so it's a true optional dependency

        self._client = Anthropic(api_key=api_key) if api_key else Anthropic()
        self._model = model
        self._top_n = top_n

    def narrate(self, report: dict) -> str:
        evidence = {
            "summary": report["summary"],
            "top_findings": report["findings"][: self._top_n],
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
