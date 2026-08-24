"""LLM-backed analyst narrative, with a deterministic offline fallback.

Live mode calls the Claude API (via the official ``anthropic`` SDK) when
``ANTHROPIC_API_KEY`` is set and the package is installed. Without a key,
:meth:`NarrativeClient.summarize` falls back to a template-driven summary
built directly from the structured findings, so the tool is fully runnable
— and testable — offline.
"""

from __future__ import annotations

import os

DEFAULT_MODEL = "claude-sonnet-5"

SYSTEM_PROMPT = (
    "You are a web application penetration tester writing the executive "
    "summary section of an assessment report. Given a target and a list of "
    "structured findings (severity, OWASP category, description), write a "
    "concise narrative: overall posture, the 2-3 findings that matter most "
    "and why, and prioritized remediation guidance. Be direct, avoid "
    "hedging, and do not invent findings beyond what's provided."
)


def build_prompt(target: str, findings: list[dict], summary: dict) -> str:
    lines = [
        f"## Target\n{target}",
        "",
        f"## Summary\nRisk score {summary['risk_score']}/100, "
        f"rating {summary['risk_rating'].upper()}, "
        f"{summary['total_findings']} findings.",
        "",
        "## Findings",
    ]
    if findings:
        for f in findings:
            lines.append(f"- [{f['severity']}] {f['title']} ({f['owasp_category']}): {f['description']}")
    else:
        lines.append("- (none)")
    return "\n".join(lines)


class NarrativeClient:
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

    def summarize(self, target: str, findings: list[dict], summary: dict) -> str:
        prompt = build_prompt(target, findings, summary)
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
                return self._offline_summary(target, findings, summary) + (
                    f"\n\n[LLM call failed, offline fallback used: {exc}]"
                )
        return self._offline_summary(target, findings, summary)

    @staticmethod
    def _offline_summary(target: str, findings: list[dict], summary: dict) -> str:
        parts = [
            "[offline heuristic summary — set ANTHROPIC_API_KEY for LLM-generated analysis]",
            f"{target}: risk rating {summary['risk_rating'].upper()} "
            f"({summary['risk_score']}/100, {summary['total_findings']} findings).",
        ]

        top = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")][:3]
        if top:
            named = "; ".join(f"{f['title']} ({f['owasp_category']})" for f in top)
            parts.append(f"Highest-priority issues: {named}.")
        elif findings:
            parts.append("No critical/high findings; remaining issues are lower severity.")
        else:
            parts.append("No findings recorded.")

        parts.append(
            "Recommended next steps: remediate critical/high findings first (credential "
            "and TLS exposure before header hardening), then re-run this audit to confirm "
            "fixes before considering the target reassessed."
        )
        return " ".join(parts)
