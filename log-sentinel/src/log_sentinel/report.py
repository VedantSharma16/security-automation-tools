"""Incident report generation from detector findings.

Two backends are provided behind a common interface:

- ``TemplateReportGenerator``: fully offline, deterministic. No network or
  API key required. This is the default, and what the test suite exercises.
- ``AnthropicReportGenerator``: sends the structured findings to Claude and
  asks for a prose incident report a human analyst can hand off. Requires
  the ``anthropic`` package and an ``ANTHROPIC_API_KEY``. Falls back to the
  template generator if either is unavailable, rather than failing the scan.
"""

from __future__ import annotations

import json
import os
import sys
from abc import ABC, abstractmethod
from dataclasses import asdict

from .detector import Finding, Severity

_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
}

_REMEDIATION = {
    "BRUTE_FORCE": (
        "Block or rate-limit the source IP, enforce account lockout / fail2ban, "
        "and require key-based SSH authentication instead of passwords."
    ),
    "CREDENTIAL_COMPROMISE_SUSPECTED": (
        "Treat the affected account as compromised: rotate its credentials, "
        "review its recent activity for lateral movement, and force re-authentication."
    ),
    "USER_ENUMERATION": (
        "Ensure SSH returns identical failure responses for valid and invalid "
        "usernames, and monitor/block the scanning source."
    ),
    "ANOMALOUS_LOGIN_TIME": (
        "Confirm the login was expected (on-call, different timezone, automation). "
        "If not, investigate the account and session."
    ),
}


def findings_to_dicts(findings: list[Finding]) -> list[dict]:
    out = []
    for f in findings:
        d = asdict(f)
        d["type"] = f.type.value
        d["severity"] = f.severity.value
        d["first_seen"] = f.first_seen.isoformat()
        d["last_seen"] = f.last_seen.isoformat()
        out.append(d)
    return out


class ReportGenerator(ABC):
    @abstractmethod
    def generate(self, findings: list[Finding], *, source_label: str) -> str:
        """Return a human-readable report (Markdown) summarizing the findings."""


class TemplateReportGenerator(ReportGenerator):
    """Deterministic, offline Markdown report. No LLM involved."""

    def generate(self, findings: list[Finding], *, source_label: str) -> str:
        lines = [f"# Incident Report: {source_label}", ""]

        if not findings:
            lines.append("No suspicious activity detected.")
            return "\n".join(lines)

        counts: dict[Severity, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        summary = ", ".join(
            f"{counts[sev]} {sev.value}"
            for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
            if sev in counts
        )
        lines.append(f"**Summary:** {len(findings)} finding(s) — {summary}.")
        lines.append("")

        for f in findings:
            emoji = _SEVERITY_EMOJI[f.severity]
            lines.append(f"## {emoji} {f.type.value} — {f.source_ip} ({f.severity.value})")
            lines.append("")
            lines.append(f.description)
            lines.append("")
            lines.append(f"- **Window:** {f.first_seen.isoformat()} → {f.last_seen.isoformat()}")
            lines.append(f"- **Events:** {f.count}")
            if f.users:
                lines.append(f"- **Account(s):** {', '.join(f.users)}")
            if f.mitre_technique:
                lines.append(f"- **MITRE ATT&CK:** {f.mitre_technique}")
            remediation = _REMEDIATION.get(f.type.value)
            if remediation:
                lines.append(f"- **Recommended action:** {remediation}")
            lines.append("")

        return "\n".join(lines)


class AnthropicReportGenerator(ReportGenerator):
    """LLM-backed report generator using the Anthropic API.

    Falls back to :class:`TemplateReportGenerator` if the ``anthropic``
    package isn't installed or ``ANTHROPIC_API_KEY`` isn't set, so a scan
    never fails just because the LLM path is unavailable.
    """

    MODEL = "claude-sonnet-5"

    def __init__(self) -> None:
        self._fallback = TemplateReportGenerator()

    def generate(self, findings: list[Finding], *, source_label: str) -> str:
        if not findings:
            return self._fallback.generate(findings, source_label=source_label)

        try:
            import anthropic
        except ImportError:
            print(
                "log-sentinel: 'anthropic' package not installed, "
                "falling back to the offline template report. "
                "Install with: pip install anthropic",
                file=sys.stderr,
            )
            return self._fallback.generate(findings, source_label=source_label)

        if not os.environ.get("ANTHROPIC_API_KEY"):
            print(
                "log-sentinel: ANTHROPIC_API_KEY not set, "
                "falling back to the offline template report.",
                file=sys.stderr,
            )
            return self._fallback.generate(findings, source_label=source_label)

        client = anthropic.Anthropic()
        findings_json = json.dumps(findings_to_dicts(findings), indent=2)
        prompt = (
            "You are a SOC analyst assistant. Given the following structured SSH "
            "auth-log findings (JSON), write a concise Markdown incident report for "
            f"'{source_label}' aimed at a hiring manager reviewing an IR workflow. "
            "Include: an executive summary, a per-finding breakdown with severity "
            "and MITRE ATT&CK context, and prioritized remediation steps. "
            "Do not invent findings beyond what's given.\n\n"
            f"Findings:\n{findings_json}"
        )

        try:
            response = client.messages.create(
                model=self.MODEL,
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}],
            )
        except Exception as exc:  # noqa: BLE001 - any API failure should degrade gracefully
            print(
                f"log-sentinel: Anthropic API call failed ({exc}), "
                "falling back to the offline template report.",
                file=sys.stderr,
            )
            return self._fallback.generate(findings, source_label=source_label)

        return "".join(block.text for block in response.content if hasattr(block, "text"))


def get_report_generator(use_llm: bool) -> ReportGenerator:
    if use_llm:
        return AnthropicReportGenerator()
    return TemplateReportGenerator()
