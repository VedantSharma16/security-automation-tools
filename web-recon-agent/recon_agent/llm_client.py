"""LLM-backed report narration, with a deterministic offline fallback.

This is a separate concern from ``planner.LLMPlanner``: that module decides
*what to do next*; this one turns the finished findings into a short,
analyst-facing narrative. Each degrades independently — you can run with a
dynamic LLM planner and an offline narrative, or vice versa.
"""

from __future__ import annotations

from ._anthropic_util import DEFAULT_MODEL, get_client
from .severity import ORDER

SYSTEM_PROMPT = (
    "You are a penetration-testing assistant writing the executive-summary section "
    "of an authorized web reconnaissance report. Given the agent's structured "
    "findings and the recon steps it performed, write a concise narrative: what was "
    "found, why it matters, and 2-4 concrete remediation steps ranked by impact. Be "
    "direct, avoid hedging when the evidence is clear, and do not invent findings "
    "that aren't present in the input."
)


def build_prompt(target: str, findings, severity: str, transcript_summary: list[str]) -> str:
    lines = ["## Target", target, "", f"## Heuristic overall risk: {severity.upper()}", "", "## Findings"]
    if findings:
        for finding in findings:
            suffix = f" ({finding.detail})" if finding.detail else ""
            lines.append(f"- [{finding.severity}] {finding.category}: {finding.summary}{suffix}")
    else:
        lines.append("- No notable findings.")

    lines += ["", "## Recon steps performed"]
    lines += [f"- {step}" for step in transcript_summary] if transcript_summary else ["- (none)"]
    return "\n".join(lines)


class Narrator:
    def __init__(self, api_key: str | None = None, model: str = DEFAULT_MODEL):
        self.model = model
        self._client = get_client(api_key)

    @property
    def is_live(self) -> bool:
        return self._client is not None

    def narrate(self, target: str, findings, severity: str, transcript_summary: list[str]) -> str:
        prompt = build_prompt(target, findings, severity, transcript_summary)
        if self._client is not None:
            try:
                response = self._client.messages.create(
                    model=self.model,
                    max_tokens=500,
                    system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": prompt}],
                )
                return "".join(
                    block.text for block in response.content if getattr(block, "type", "") == "text"
                ).strip()
            except Exception as exc:  # pragma: no cover - network/SDK failure path
                return self._offline_narrative(findings, severity) + f"\n\n[LLM call failed, offline fallback used: {exc}]"
        return self._offline_narrative(findings, severity)

    @staticmethod
    def _offline_narrative(findings, severity: str) -> str:
        parts = [
            "[offline heuristic narrative — set ANTHROPIC_API_KEY for LLM-generated analysis]",
            f"Overall risk: {severity.upper()}.",
        ]
        if findings:
            ranked = sorted(findings, key=lambda f: ORDER.index(f.severity) if f.severity in ORDER else len(ORDER))
            top = ranked[:3]
            parts.append("Top findings: " + "; ".join(f.summary for f in top) + ".")
        else:
            parts.append("No significant issues were identified by the automated checks.")
        parts.append(
            "Recommended next steps: manually validate each finding, prioritize remediation of "
            "high/critical items first, and re-run recon after fixes to confirm closure."
        )
        return " ".join(parts)
