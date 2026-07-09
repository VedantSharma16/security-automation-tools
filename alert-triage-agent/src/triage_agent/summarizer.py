"""Turns a list of rule matches into a human-readable triage report.

Two implementations share one interface (`summarize`):

- RuleBasedSummarizer: deterministic, offline, no external dependencies.
  This is the default so the tool is fully usable and testable without
  any API key or network access.
- AnthropicSummarizer: optional. Sends the (already-filtered, already
  de-duplicated) findings to Claude to produce an analyst-style writeup
  with prioritized next steps. Only imports `anthropic` when actually
  used, so it stays an optional dependency.
"""

from __future__ import annotations

import os
from collections import Counter
from typing import Protocol

from .models import Finding, Severity, TriageReport

DEFAULT_MODEL = "claude-sonnet-5"


class Summarizer(Protocol):
    def summarize(self, findings: list[Finding], total_events: int) -> TriageReport: ...


class RuleBasedSummarizer:
    """Deterministic summary: severity/technique breakdown + top findings."""

    name = "rule-based"

    def summarize(self, findings: list[Finding], total_events: int) -> TriageReport:
        stats = {
            "total_events": total_events,
            "total_findings": len(findings),
        }
        by_severity = Counter(f.severity for f in findings)
        for sev in Severity:
            stats[f"severity_{sev.name.lower()}"] = by_severity.get(sev, 0)

        if not findings:
            summary = f"Scanned {total_events} log lines. No rule matches — nothing to triage."
            return TriageReport(findings=findings, summary=summary, generated_by=self.name, stats=stats)

        ordered = sorted(findings, key=lambda f: f.severity, reverse=True)
        technique_counts = Counter(f.rule.mitre_technique for f in findings)

        lines = [
            f"Scanned {total_events} log lines, {len(findings)} rule match(es):",
            "  " + ", ".join(f"{sev.name.lower()}={by_severity.get(sev, 0)}" for sev in reversed(list(Severity))),
            "",
            "Top ATT&CK techniques observed:",
        ]
        for technique, count in technique_counts.most_common(5):
            lines.append(f"  - {technique} ({count} match{'es' if count != 1 else ''})")

        lines.append("")
        lines.append("Highest-severity findings:")
        for f in ordered[:10]:
            lines.append(
                f"  [{f.severity.name}] {f.rule.id} {f.rule.name} "
                f"(line {f.event.line_number}): {f.event.raw.strip()[:160]}"
            )

        return TriageReport(findings=findings, summary="\n".join(lines), generated_by=self.name, stats=stats)


class AnthropicSummarizer:
    """LLM-backed narrative summary, used with --llm. Requires ANTHROPIC_API_KEY."""

    def __init__(self, model: str = DEFAULT_MODEL, max_findings: int = 40):
        self.model = model
        self.max_findings = max_findings
        self.name = f"claude:{model}"

    def summarize(self, findings: list[Finding], total_events: int) -> TriageReport:
        try:
            import anthropic
        except ImportError as exc:
            raise RuntimeError(
                "The 'anthropic' package is required for --llm. Install it with "
                "`pip install alert-triage-agent[ai]`."
            ) from exc

        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise RuntimeError("ANTHROPIC_API_KEY is not set; cannot use --llm.")

        base = RuleBasedSummarizer().summarize(findings, total_events)
        if not findings:
            return TriageReport(findings=findings, summary=base.summary, generated_by=self.name, stats=base.stats)

        ordered = sorted(findings, key=lambda f: f.severity, reverse=True)[: self.max_findings]
        findings_block = "\n".join(
            f"- id={f.rule.id} severity={f.severity.name} technique={f.rule.mitre_technique} "
            f"line={f.event.line_number} text={f.event.raw.strip()[:200]!r}"
            for f in ordered
        )

        prompt = (
            "You are a SOC analyst triaging automated detection output. Below are rule "
            "matches from a log scan, each with a severity, a MITRE ATT&CK technique, and "
            "the offending line. Write a concise incident triage report with:\n"
            "1. A one-paragraph executive summary.\n"
            "2. The most likely attack narrative connecting related findings, if any.\n"
            "3. Prioritized, concrete next actions for an analyst.\n"
            "Be direct and specific; do not restate the raw findings verbatim.\n\n"
            f"Total log lines scanned: {total_events}\n"
            f"Findings ({len(findings)} total, showing top {len(ordered)} by severity):\n"
            f"{findings_block}"
        )

        client = anthropic.Anthropic()
        response = client.messages.create(
            model=self.model,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(block.text for block in response.content if getattr(block, "type", None) == "text")

        return TriageReport(findings=findings, summary=text.strip(), generated_by=self.name, stats=base.stats)
