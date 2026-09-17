"""LLM-backed SOC-analyst narrative for a finished report, with a
deterministic offline fallback so the tool is fully usable without an API key.
"""

from __future__ import annotations

import os

DEFAULT_MODEL = "claude-sonnet-5"

SYSTEM_PROMPT = (
    "You are a SOC analyst writing the closing summary of a phishing triage report. "
    "Given the structured findings for one email, write 3-5 concise sentences: what "
    "this message is trying to do, the strongest evidence for or against it being "
    "phishing, and a concrete recommended action (e.g. quarantine, block sender domain, "
    "notify the recipient, escalate to IR). Cite specific findings, not generic advice. "
    "If the findings are weak or absent, say so plainly rather than inventing risk."
)


def _build_prompt(report: dict) -> str:
    msg = report["message"]
    lines = [
        f"Subject: {msg['subject']}",
        f"From: {msg['from_display_name']} <{msg['from_addr']}>",
        f"Overall severity: {report['summary']['highest_severity']}",
        f"Risk score: {report['summary']['risk_score']}/100",
        "Findings:",
    ]
    for finding in report["findings"]:
        lines.append(f"- [{finding['severity']}] {finding['title']} — {finding['detail']}")
    if not report["findings"]:
        lines.append("- (none)")
    return "\n".join(lines)


def _offline_narrative(report: dict) -> str:
    findings = report["findings"]
    prefix = "[offline heuristic summary — set ANTHROPIC_API_KEY for an LLM-generated narrative] "
    if not findings:
        return prefix + "No phishing indicators detected; treat as low priority pending analyst review."

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    worst = sorted(findings, key=lambda f: order.get(f["severity"], 5))[0]
    summary = report["summary"]
    return (
        prefix
        + f"{summary['total_findings']} finding(s), overall severity {summary['highest_severity']} "
        f"(risk score {summary['risk_score']}/100). Highest-priority issue: {worst['title']} — "
        f"{worst['detail']} Recommend escalating to IR if severity is HIGH or CRITICAL; "
        "otherwise have an analyst confirm before closing out."
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

    def write(self, report: dict) -> str:
        if self._client is not None:
            try:
                response = self._client.messages.create(
                    model=self.model,
                    max_tokens=400,
                    system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": _build_prompt(report)}],
                )
                return "".join(
                    block.text for block in response.content if getattr(block, "type", "") == "text"
                ).strip()
            except Exception as exc:  # pragma: no cover - network/SDK failure path
                return _offline_narrative(report) + f"\n\n[LLM call failed, offline fallback used: {exc}]"
        return _offline_narrative(report)
