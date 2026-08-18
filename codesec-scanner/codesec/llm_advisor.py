"""Pluggable remediation-narrative generators for the scan report.

The structured findings (rule, severity, CWE, location) are the source of
truth; an advisor only turns them into prioritized prose for a human
reviewer. This keeps any LLM call grounded in what the deterministic
detectors already verified, rather than asking the model to re-read source
and invent its own findings.

TemplateAdvisor is deterministic, dependency-free, and always available --
it's the default, and what tests and CI run against. AnthropicAdvisor is
opt-in (`--llm`) and requires the `anthropic` package plus an API key; if
either is missing, `get_advisor` falls back to the template advisor and
prints a note explaining why.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Protocol

SYSTEM_PROMPT = (
    "You are an application security engineer writing the remediation-guidance "
    "section of an automated SAST report. You are given ONLY a JSON object of "
    "structured findings already produced by static analysis rules -- you have "
    "no access to the original source. Do not invent findings, files, or lines "
    "that are not present in the JSON. Write three short sections: "
    "'Overall Risk', 'Priority Fixes' (reference specific rule_ids and files), "
    "and 'Suggested Fix Order'. Be concise and concrete."
)


class Advisor(Protocol):
    def advise(self, report: dict) -> str: ...


class TemplateAdvisor:
    """Deterministic, offline narrative built directly from the report's findings."""

    def advise(self, report: dict) -> str:
        findings = report["findings"]
        summary = report["summary"]

        if not findings:
            return "No findings were detected. No remediation action is required."

        by_severity = summary["by_severity"]
        lines = [
            f"{summary['total_findings']} finding(s) across {summary['files_scanned']} file(s). "
            f"Severity breakdown: "
            + ", ".join(f"{name}={count}" for name, count in by_severity.items() if count),
            "",
        ]

        critical_high = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
        if critical_high:
            lines.append("Priority fixes (CRITICAL/HIGH):")
            for f in critical_high[:10]:
                lines.append(f"  - [{f['rule_id']}] {f['file']}:{f['line']} -- {f['title']}")
            if len(critical_high) > 10:
                lines.append(f"  ... and {len(critical_high) - 10} more.")
            lines.append("")

        rule_ids = {f["rule_id"] for f in findings}
        if "py-sql-injection" in rule_ids or any(r.startswith("secret-") for r in rule_ids):
            lines.append(
                "Treat any hardcoded credential as already compromised: rotate it "
                "regardless of exposure. SQL built via string interpolation should "
                "move to parameterized queries before anything else, since it is "
                "directly exploitable."
            )

        lines.append("")
        lines.append(
            "Suggested fix order: CRITICAL findings first (secrets, injection), "
            "then HIGH (unsafe deserialization, disabled TLS verification), "
            "then MEDIUM/LOW as time allows."
        )
        return "\n".join(lines)


class AnthropicAdvisor:
    """Sends the structured findings (not raw source) to a Claude model for remediation guidance."""

    def __init__(self, model: str = "claude-sonnet-5", api_key: str | None = None):
        from anthropic import Anthropic  # imported lazily so it's a true optional dependency

        self._client = Anthropic(api_key=api_key) if api_key else Anthropic()
        self._model = model

    def advise(self, report: dict) -> str:
        evidence = {"summary": report["summary"], "findings": report["findings"]}
        response = self._client.messages.create(
            model=self._model,
            max_tokens=700,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": json.dumps(evidence, indent=2)}],
        )
        return "".join(block.text for block in response.content if block.type == "text")


def get_advisor(use_llm: bool, model: str = "claude-sonnet-5") -> Advisor:
    """Return an AnthropicAdvisor if requested and usable, else TemplateAdvisor."""
    if not use_llm:
        return TemplateAdvisor()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print(
            "note: --llm requested but ANTHROPIC_API_KEY is not set; "
            "falling back to the offline template advisor.",
            file=sys.stderr,
        )
        return TemplateAdvisor()

    try:
        return AnthropicAdvisor(model=model, api_key=api_key)
    except ImportError:
        print(
            "note: --llm requested but the 'anthropic' package is not installed; "
            "falling back to the offline template advisor.",
            file=sys.stderr,
        )
        return TemplateAdvisor()
