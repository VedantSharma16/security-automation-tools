"""LLM-backed remediation narrative, with a deterministic offline fallback.

Live mode calls the Claude API (via the official ``anthropic`` SDK) when
``ANTHROPIC_API_KEY`` is set and the package is installed. Without a key,
:meth:`LLMNarrator.narrate` falls back to a template-driven summary built
directly from the structured findings, so the tool is fully runnable — and
testable — offline.
"""

from __future__ import annotations

import os

from http_audit.report import AuditReport

DEFAULT_MODEL = "claude-sonnet-5"

SYSTEM_PROMPT = (
    "You are an application security consultant writing up the results of a passive "
    "HTTP configuration audit for a client. Given a list of findings with severities, "
    "write a concise remediation-prioritized summary: what the biggest risks are, why "
    "they matter in plain business terms, and the order in which the client should fix "
    "them. Be direct, avoid hedging, and do not invent findings that weren't given."
)


def build_prompt(report: AuditReport) -> str:
    lines = [f"## Audit target: {report.url}", f"Score: {report.score}/100 (grade {report.grade})", "", "## Findings"]
    for f in report.sorted_findings():
        if f.severity == "pass":
            continue
        rec = f" Recommendation: {f.recommendation}" if f.recommendation else ""
        lines.append(f"- [{f.severity.upper()}] ({f.category}) {f.name}: {f.message}{rec}")
    if all(f.severity == "pass" for f in report.findings):
        lines.append("- No issues found; every check passed.")
    return "\n".join(lines)


class LLMNarrator:
    """Wraps Anthropic API access with a safe offline fallback."""

    def __init__(self, api_key: str | None = None, model: str = DEFAULT_MODEL):
        self.model = model
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._client = None
        if self.api_key:
            try:
                import anthropic  # type: ignore

                self._client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                self._client = None

    @property
    def is_live(self) -> bool:
        return self._client is not None

    def narrate(self, report: AuditReport) -> str:
        prompt = build_prompt(report)
        if self._client is not None:
            try:
                response = self._client.messages.create(
                    model=self.model,
                    max_tokens=600,
                    system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": prompt}],
                )
                return "".join(
                    block.text for block in response.content if getattr(block, "type", "") == "text"
                ).strip()
            except Exception as exc:  # pragma: no cover - network/SDK failure path
                return self._offline_narrative(report) + f"\n\n[LLM call failed, offline fallback used: {exc}]"
        return self._offline_narrative(report)

    @staticmethod
    def _offline_narrative(report: AuditReport) -> str:
        actionable = [f for f in report.findings if f.severity not in ("pass", "info")]
        parts = [
            "[offline heuristic summary — set ANTHROPIC_API_KEY for LLM-generated analysis]",
            f"Grade {report.grade} ({report.score}/100).",
        ]

        if not actionable:
            parts.append("No actionable issues found; all checks passed.")
            return " ".join(parts)

        worst = report.sorted_findings()
        top = [f for f in worst if f.severity in ("critical", "high")][:3]
        if top:
            names = "; ".join(f"{f.name} ({f.severity})" for f in top)
            parts.append(f"Highest-priority issues: {names}.")
        parts.append(
            f"{len(actionable)} total issue(s) found across headers, cookies, CORS, and TLS checks. "
            "Fix critical/high findings first (they represent direct exploitation or data-exposure risk), "
            "then medium/low findings as defense-in-depth hardening."
        )
        return " ".join(parts)
