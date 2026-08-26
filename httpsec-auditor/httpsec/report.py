"""Console (human) and JSON report rendering."""

from __future__ import annotations

import json

from .models import Finding
from .scoring import ScoreResult

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

_ANSI = {
    "critical": "\033[1;41m",  # bold, red background
    "high": "\033[1;31m",  # bold red
    "medium": "\033[1;33m",  # bold yellow
    "low": "\033[36m",  # cyan
    "info": "\033[90m",  # gray
    "reset": "\033[0m",
    "bold": "\033[1m",
}


def _color(text: str, code: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{_ANSI[code]}{text}{_ANSI['reset']}"


def sort_findings(findings: list[Finding]) -> list[Finding]:
    order = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
    return sorted(findings, key=lambda f: order.get(f.severity, len(order)))


def render_console(
    target: str,
    findings: list[Finding],
    score: ScoreResult,
    use_color: bool = True,
) -> str:
    lines = []
    lines.append(_color(f"httpsec-auditor report for {target}", "bold", use_color))
    lines.append(
        f"Score: {_color(str(score.score), 'bold', use_color)}/100  "
        f"Grade: {_color(score.grade, 'bold', use_color)}"
    )
    summary_bits = [f"{score.counts.get(sev, 0)} {sev}" for sev in SEVERITY_ORDER]
    lines.append("Findings: " + ", ".join(summary_bits))
    lines.append("")

    if not findings:
        lines.append(_color("No findings. Looking good.", "low", use_color))
        return "\n".join(lines)

    for finding in sort_findings(findings):
        badge = _color(f"[{finding.severity.upper()}]", finding.severity, use_color)
        lines.append(f"{badge} {finding.title}  ({finding.category}/{finding.id})")
        lines.append(f"    {finding.description}")
        lines.append(f"    Remediation: {finding.remediation}")
        if finding.evidence:
            lines.append(f"    Evidence: {finding.evidence}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render_json(target: str, findings: list[Finding], score: ScoreResult) -> str:
    payload = {
        "target": target,
        "score": score.score,
        "grade": score.grade,
        "counts": score.counts,
        "findings": [f.to_dict() for f in sort_findings(findings)],
    }
    return json.dumps(payload, indent=2)
