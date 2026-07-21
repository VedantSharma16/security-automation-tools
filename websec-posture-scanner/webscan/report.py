"""Render a ScanResult as plain text, Markdown, or JSON."""

from __future__ import annotations

import json
from dataclasses import asdict

from .grading import SEVERITY_WEIGHTS
from .models import ScanResult

_SEVERITY_ORDER = tuple(SEVERITY_WEIGHTS.keys())


def _sorted_findings(result: ScanResult):
    return sorted(result.findings, key=lambda f: _SEVERITY_ORDER.index(f.severity))


def render_text(result: ScanResult) -> str:
    lines = [
        f"Web Security Posture Scan: {result.target_url}",
        f"Grade: {result.grade}  (score {result.score}/100)",
        f"Findings: {len(result.findings)}",
        "",
    ]

    if result.tls:
        if result.tls.error:
            lines.append(f"TLS: handshake failed ({result.tls.error})")
        else:
            lines.append(
                f"TLS: {result.tls.protocol_version} / {result.tls.cipher} "
                f"(expires in {result.tls.days_until_expiry} days)"
            )
        lines.append("")

    if not result.findings:
        lines.append("No findings.")
        return "\n".join(lines)

    for finding in _sorted_findings(result):
        lines.append(f"[{finding.severity.upper():<8}] {finding.title} ({finding.category})")
        lines.append(f"    {finding.description}")
        lines.append(f"    Fix: {finding.remediation}")
        if finding.evidence:
            lines.append(f"    Evidence: {finding.evidence}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render_markdown(result: ScanResult) -> str:
    lines = [
        f"# Web Security Posture Scan: {result.target_url}",
        "",
        f"**Grade:** {result.grade} &nbsp;|&nbsp; **Score:** {result.score}/100 "
        f"&nbsp;|&nbsp; **Findings:** {len(result.findings)}",
        "",
    ]

    if result.tls:
        lines.append("## TLS")
        lines.append("")
        if result.tls.error:
            lines.append(f"Handshake failed: `{result.tls.error}`")
        else:
            lines.append(f"- Protocol: `{result.tls.protocol_version}`")
            lines.append(f"- Cipher: `{result.tls.cipher}`")
            lines.append(f"- Expires: {result.tls.not_after} ({result.tls.days_until_expiry} days)")
        lines.append("")

    lines.append("## Findings")
    lines.append("")

    if not result.findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"

    lines.append("| Severity | Title | Category |")
    lines.append("|---|---|---|")
    for finding in _sorted_findings(result):
        lines.append(f"| {finding.severity.upper()} | {finding.title} | {finding.category} |")
    lines.append("")

    for finding in _sorted_findings(result):
        lines.append(f"### {finding.title}")
        lines.append("")
        lines.append(f"- **Severity:** {finding.severity}")
        lines.append(f"- **Category:** {finding.category}")
        lines.append(f"- **Description:** {finding.description}")
        lines.append(f"- **Remediation:** {finding.remediation}")
        if finding.evidence:
            lines.append(f"- **Evidence:** `{finding.evidence}`")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render_json(result: ScanResult) -> str:
    return json.dumps(asdict(result), indent=2)
