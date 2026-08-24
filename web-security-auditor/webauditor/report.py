"""Assemble the structured report and render it as console/JSON/Markdown."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .findings import Finding
from .scoring import build_summary

_SEVERITY_COLOR = {
    "INFO": "\033[90m",       # gray
    "LOW": "\033[36m",        # cyan
    "MEDIUM": "\033[33m",     # yellow
    "HIGH": "\033[31m",       # red
    "CRITICAL": "\033[1;31m",  # bold red
}
_RESET = "\033[0m"

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def build_report(target: str, findings: list[Finding], narrative: str | None = None) -> dict:
    findings_sorted = sorted(findings, key=lambda f: _SEVERITY_ORDER.index(f.severity.name))
    return {
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": [f.to_dict() for f in findings_sorted],
        "summary": build_summary(findings),
        "narrative": narrative,
    }


def filter_by_min_severity(report: dict, min_severity: str) -> dict:
    threshold = _SEVERITY_ORDER.index(min_severity.upper())
    filtered = [f for f in report["findings"] if _SEVERITY_ORDER.index(f["severity"]) <= threshold]
    report = dict(report)
    report["findings"] = filtered
    return report


def render_console(report: dict, use_color: bool = True) -> str:
    lines = [f"Web Security Auditor — {report['target']}"]
    lines.append(f"Generated: {report['generated_at']}")

    summary = report["summary"]
    lines.append("")
    lines.append(
        f"Findings: {summary['total_findings']}  |  "
        f"Risk score: {summary['risk_score']}/100  |  "
        f"Rating: {summary['risk_rating'].upper()}"
    )

    if not report["findings"]:
        lines.append("No findings. ✅")
    else:
        lines.append("")
        for f in report["findings"]:
            color = _SEVERITY_COLOR.get(f["severity"], "") if use_color else ""
            reset = _RESET if use_color else ""
            lines.append(f"{color}[{f['severity']:8}]{reset} {f['title']} ({f['owasp_category']})")
            if f["evidence"]:
                lines.append(f"           evidence: {f['evidence']}")
            if f["remediation"]:
                lines.append(f"           fix: {f['remediation']}")

    if report.get("narrative"):
        lines.append("")
        lines.append("--- Analyst narrative ---")
        lines.append(report["narrative"])

    return "\n".join(lines)


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def to_markdown(report: dict) -> str:
    summary = report["summary"]
    lines = [f"# Web Security Audit: {report['target']}", ""]
    lines.append(f"Generated: {report['generated_at']}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Total findings: {summary['total_findings']}")
    lines.append(f"- Risk score: {summary['risk_score']}/100")
    lines.append(f"- Risk rating: {summary['risk_rating'].upper()}")
    for sev, count in summary["by_severity"].items():
        if count:
            lines.append(f"  - {sev}: {count}")
    lines.append("")

    if report["findings"]:
        lines.append("## Findings")
        lines.append("")
        for f in report["findings"]:
            lines.append(f"### [{f['severity']}] {f['title']}")
            lines.append("")
            lines.append(f"**OWASP category:** {f['owasp_category']}")
            lines.append("")
            lines.append(f["description"])
            if f["evidence"]:
                lines.append("")
                lines.append(f"**Evidence:** `{f['evidence']}`")
            if f["remediation"]:
                lines.append("")
                lines.append(f"**Remediation:** {f['remediation']}")
            lines.append("")

    if report.get("narrative"):
        lines.append("## Analyst Narrative")
        lines.append("")
        lines.append(report["narrative"])
        lines.append("")

    return "\n".join(lines)


def write_json(report: dict, path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
