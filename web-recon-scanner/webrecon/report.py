"""Aggregate findings from every recon module into a single scan report,
with console, dict, and JSON renderings and an overall risk score/grade.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_WEIGHTS = {"info": 0, "low": 1, "medium": 3, "high": 7, "critical": 12}
SEVERITY_COLORS = {
    "critical": "\033[91m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[90m",
}
RESET = "\033[0m"


@dataclass
class ScanReport:
    target: str
    scanned_at: str
    header_findings: list = field(default_factory=list)
    tls_report: object = None
    technologies: list = field(default_factory=list)
    robots_findings: object = None
    sitemap_urls: list = field(default_factory=list)
    subdomains: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def build_report(target: str, scanned_at: str | None = None, **kwargs) -> ScanReport:
    return ScanReport(target=target, scanned_at=scanned_at or datetime.now(timezone.utc).isoformat(), **kwargs)


def _all_findings(report: ScanReport):
    """Flatten every non-informational finding into (severity, source, message) tuples."""
    findings = []

    for hf in report.header_findings:
        if hf.severity != "info":
            findings.append((hf.severity, f"header:{hf.header}", hf.message))

    if report.tls_report:
        for f in report.tls_report.findings:
            if f.severity != "info":
                findings.append((f.severity, "tls", f.message))

    if report.robots_findings:
        for path in report.robots_findings.sensitive_paths:
            findings.append(("low", "robots.txt", f"Disallowed path hints at something sensitive: {path}"))

    return findings


def risk_score(report: ScanReport) -> int:
    return sum(SEVERITY_WEIGHTS.get(severity, 0) for severity, _, _ in _all_findings(report))


def risk_grade(score: int) -> str:
    if score == 0:
        return "A"
    if score <= 5:
        return "B"
    if score <= 12:
        return "C"
    if score <= 25:
        return "D"
    return "F"


def filter_by_min_severity(findings, min_severity: str):
    threshold = SEVERITY_WEIGHTS.get(min_severity, 0)
    return [f for f in findings if SEVERITY_WEIGHTS.get(f[0], 0) >= threshold]


def render_console(report: ScanReport, use_color: bool = True) -> str:
    findings = sorted(_all_findings(report), key=lambda item: -SEVERITY_WEIGHTS.get(item[0], 0))
    score = risk_score(report)
    grade = risk_grade(score)

    lines = [
        f"Web Recon Report: {report.target}",
        f"Scanned at: {report.scanned_at}",
        f"Risk score: {score}  Grade: {grade}",
        "",
    ]

    if report.technologies:
        lines.append("Detected technologies:")
        for tech in report.technologies:
            lines.append(f"  - {tech.name} ({tech.category}) — {tech.evidence}")
        lines.append("")

    if report.tls_report:
        tls = report.tls_report
        lines.append(
            f"TLS: {tls.protocol_version or 'unknown'}, subject={tls.subject_cn!r}, "
            f"issuer={tls.issuer_cn!r}, expires_in={tls.days_until_expiry} day(s)"
        )
        lines.append("")

    if findings:
        lines.append(f"Findings ({len(findings)}):")
        for severity, source, message in findings:
            color = SEVERITY_COLORS.get(severity, "") if use_color else ""
            reset = RESET if use_color else ""
            lines.append(f"  {color}[{severity.upper():8}]{reset} ({source}) {message}")
    else:
        lines.append("No issues found.")

    if report.subdomains:
        lines.append("")
        lines.append(f"Resolved subdomains ({len(report.subdomains)}):")
        for sub in report.subdomains:
            lines.append(f"  - {sub.subdomain} -> {sub.address}")

    if report.errors:
        lines.append("")
        lines.append("Errors (module skipped or failed):")
        for error in report.errors:
            lines.append(f"  - {error}")

    return "\n".join(lines)


def to_dict(report: ScanReport) -> dict:
    data = asdict(report)
    data["risk_score"] = risk_score(report)
    data["risk_grade"] = risk_grade(data["risk_score"])
    return data


def write_json(report: ScanReport, path: Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(to_dict(report), f, indent=2, default=str)
