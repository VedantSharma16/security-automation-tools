"""Optional LLM-written executive summary, grounded strictly in findings.

Same shape as the other tools in this repo: the model never sees raw
network traffic, only the structured findings already produced by the
deterministic checks, and is instructed not to introduce claims beyond
that evidence. Without ``ANTHROPIC_API_KEY`` (or the ``llm`` extra
installed), :func:`summarize` falls back to a deterministic offline
template, so the tool is always usable without network access or a key.
"""

from __future__ import annotations

import os

from .findings import Finding
from .scoring import RiskAssessment

DEFAULT_MODEL = "claude-sonnet-5"

SYSTEM_PROMPT = (
    "You are a penetration tester writing the executive summary section of "
    "an attack-surface report for a client. You are given a structured list "
    "of findings already produced by deterministic checks (HTTP header "
    "analysis, sensitive path probing, TLS inspection) plus an overall risk "
    "score. Write 3-5 sentences: what the most important exposure is, the "
    "realistic impact if exploited, and the top priority to fix first. Do "
    "not invent findings that are not in the evidence provided, and do not "
    "hedge on findings the evidence makes clear."
)


def build_prompt(target: str, findings: list[Finding], risk: RiskAssessment) -> str:
    lines = [
        f"## Target\n{target}",
        f"\n## Overall risk: {risk.overall_severity.upper()} (score {risk.score}/100)",
        f"Severity breakdown: {risk.severity_counts}",
        "\n## Findings",
    ]
    if findings:
        for f in sorted(findings, key=lambda f: f.severity, reverse=True):
            lines.append(f"- [{f.severity.upper()}] ({f.category}) {f.title}: {f.detail}")
    else:
        lines.append("- No findings were raised by any check.")
    return "\n".join(lines)


class LLMSummarizer:
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

    def summarize(self, target: str, findings: list[Finding], risk: RiskAssessment) -> str:
        prompt = build_prompt(target, findings, risk)
        if self._client is not None:
            try:
                response = self._client.messages.create(
                    model=self.model,
                    max_tokens=400,
                    system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": prompt}],
                )
                return "".join(
                    block.text for block in response.content if getattr(block, "type", "") == "text"
                ).strip()
            except Exception as exc:  # pragma: no cover - network/SDK failure path
                return self._offline_summary(target, findings, risk) + (
                    f"\n\n[LLM call failed, offline fallback used: {exc}]"
                )
        return self._offline_summary(target, findings, risk)

    @staticmethod
    def _offline_summary(target: str, findings: list[Finding], risk: RiskAssessment) -> str:
        parts = [
            "[offline heuristic summary — set ANTHROPIC_API_KEY for an LLM-generated analysis]",
            f"Overall risk for {target}: {risk.overall_severity.upper()} "
            f"(score {risk.score}/100).",
        ]
        if not findings:
            parts.append("No findings were raised by any check.")
            return " ".join(parts)

        worst = max(findings, key=lambda f: ["info", "low", "medium", "high", "critical"].index(f.severity))
        parts.append(f"Top finding: {worst.title} ({worst.severity}) — {worst.recommendation}")
        others = len(findings) - 1
        if others > 0:
            parts.append(f"{others} additional finding(s) were raised across "
                          f"{len({f.category for f in findings})} check categories; "
                          "see the full report for details.")
        return " ".join(parts)
