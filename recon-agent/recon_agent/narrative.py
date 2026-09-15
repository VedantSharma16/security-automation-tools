"""LLM-backed executive narrative for a finished ReconReport, with a
deterministic offline fallback so the tool is fully usable without an API key.
"""

from __future__ import annotations

import os

DEFAULT_MODEL = "claude-sonnet-5"

SYSTEM_PROMPT = (
    "You are a penetration testing report writer. Given the structured "
    "findings from an authorized reconnaissance pass, write a short "
    "executive summary (3-5 sentences): what was discovered, the single "
    "biggest risk, and the top priority remediation. Be concrete and cite "
    "specific ports/headers/hosts from the findings, not generic advice."
)


def _build_prompt(report_dict: dict) -> str:
    lines = [f"Target: {report_dict['target']}", f"Overall severity: {report_dict['overall_severity']}", "Findings:"]
    for finding in report_dict["findings"]:
        lines.append(f"- [{finding['severity']}] {finding['title']} — {finding['detail']}")
    if not report_dict["findings"]:
        lines.append("- (none)")
    return "\n".join(lines)


def _offline_narrative(report_dict: dict) -> str:
    findings = report_dict["findings"]
    if not findings:
        return (
            "[offline heuristic summary — set ANTHROPIC_API_KEY for an LLM-generated narrative] "
            f"No notable findings for {report_dict['target']}; overall severity is informational."
        )

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    worst = sorted(findings, key=lambda f: order.get(f["severity"], 5))[0]
    return (
        "[offline heuristic summary — set ANTHROPIC_API_KEY for an LLM-generated narrative] "
        f"{len(findings)} finding(s) for {report_dict['target']}, overall severity "
        f"{report_dict['overall_severity'].upper()}. Highest-priority issue: {worst['title']} "
        f"({worst['detail']}). Recommend addressing {worst['severity']}-severity findings first, "
        "then re-running the scan to confirm remediation."
    )


class NarrativeWriter:
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

    def write(self, report_dict: dict) -> str:
        if self._client is not None:
            try:
                response = self._client.messages.create(
                    model=self.model,
                    max_tokens=400,
                    system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": _build_prompt(report_dict)}],
                )
                return "".join(
                    block.text for block in response.content if getattr(block, "type", "") == "text"
                ).strip()
            except Exception as exc:  # pragma: no cover - network/SDK failure path
                return _offline_narrative(report_dict) + f"\n\n[LLM call failed, offline fallback used: {exc}]"
        return _offline_narrative(report_dict)
