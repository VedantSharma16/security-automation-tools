"""Turn the consolidated, structured report into prose for a human analyst.

Same pattern as ``logtriage.llm_summarizer``: the LLM (when used) is shown
only the structured report already produced by the deterministic tools and
aggregator, and is explicitly told not to introduce facts beyond it. The
template summarizer is dependency-free and is what tests run against.
"""

from __future__ import annotations

import json
import os
from typing import Protocol

from .aggregator import recommended_actions

DEFAULT_MODEL = "claude-sonnet-5"

SYSTEM_PROMPT = (
    "You are a SOC analyst writing the executive narrative for an automated, "
    "multi-tool incident triage report. You are given ONLY a JSON object "
    "produced by deterministic rule-based tools and an aggregator -- you have "
    "no access to raw logs or any other source. Do not invent facts, IPs, "
    "hashes, usernames, or events not present in the JSON. Write three short "
    "sections: 'Executive Summary', 'What Happened' (state clearly if evidence "
    "across tools is insufficient to build a narrative), and 'Recommended "
    "Actions'. Be concise and specific; prefer details from the evidence over "
    "generic advice."
)


class Narrator(Protocol):
    def narrate(self, report: dict) -> str: ...


class TemplateNarrator:
    """Deterministic, offline narrative built directly from the aggregated report."""

    def narrate(self, report: dict) -> str:
        if report["total_findings"] == 0 and not report["tools_errored"]:
            return (
                "No security-relevant findings were produced by the tool(s) run "
                f"({', '.join(report['tools_run']) or 'none'}). No further action recommended."
            )

        lines = [
            f"Overall severity: {report['overall_severity'].upper()}.",
            f"{report['total_findings']} total finding(s) across {len(report['tools_run'])} tool(s) "
            f"({', '.join(report['tools_run']) or 'none'}).",
        ]
        if report["tools_skipped"]:
            lines.append(f"Skipped (not applicable to this evidence): {', '.join(report['tools_skipped'])}.")
        if report["tools_errored"]:
            lines.append(f"Could not run (see tool_results for detail): {', '.join(report['tools_errored'])}.")

        for name, result in report["tool_results"].items():
            if result["status"] == "ok" and result["headline"]:
                lines.append(f"- [{name}] {result['headline']}")

        lines.append("")
        lines.append("Recommended actions:")
        for action in recommended_actions(report):
            lines.append(f"- {action}")

        return "\n".join(lines)


class AnthropicNarrator:
    """Sends the structured, aggregated report (not raw evidence) to Claude for narrative synthesis."""

    def __init__(self, model: str = DEFAULT_MODEL, api_key: str | None = None):
        from anthropic import Anthropic  # imported lazily so it's a true optional dependency

        self._client = Anthropic(api_key=api_key) if api_key else Anthropic()
        self._model = model

    def narrate(self, report: dict) -> str:
        evidence = {
            "overall_severity": report["overall_severity"],
            "total_findings": report["total_findings"],
            "tools_run": report["tools_run"],
            "tools_skipped": report["tools_skipped"],
            "tools_errored": report["tools_errored"],
            "tool_results": {
                name: {k: v for k, v in result.items() if k != "raw"} | {"raw_summary": _summarize_raw(result)}
                for name, result in report["tool_results"].items()
            },
        }
        response = self._client.messages.create(
            model=self._model,
            max_tokens=700,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": json.dumps(evidence, indent=2)}],
        )
        return "".join(block.text for block in response.content if getattr(block, "type", "") == "text")


def _summarize_raw(result: dict) -> dict | None:
    """Trim each tool's raw payload to the fields worth showing the narrator,
    keeping the prompt small and avoiding dumping e.g. full alert text back in."""
    raw = result.get("raw")
    if not raw:
        return None
    if result["tool"] == "log_triage":
        return {"findings": raw.get("findings", [])}
    if result["tool"] == "ioc_triage":
        return {
            "indicators": raw.get("indicators", []),
            "malicious_hits": [e for e in raw.get("enrichment", []) if e["is_known_malicious"]],
            "matched_techniques": raw.get("matched_techniques", []),
        }
    if result["tool"] == "process_hunter":
        return {"findings": raw.get("findings", [])}
    return raw


def get_narrator(use_llm: bool, model: str = DEFAULT_MODEL) -> Narrator:
    if not use_llm:
        return TemplateNarrator()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return TemplateNarrator()

    try:
        return AnthropicNarrator(model=model, api_key=api_key)
    except ImportError:
        return TemplateNarrator()
