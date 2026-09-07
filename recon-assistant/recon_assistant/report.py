"""Builds the structured report dict and renders it as JSON or Markdown."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from . import scoring
from .fingerprint import Finding
from .scanner import PortResult


def build_report(
    target: str,
    resolved_ip: str,
    port_results: list[PortResult],
    findings: list[Finding],
    scanned_at: datetime | None = None,
) -> dict:
    scanned_at = scanned_at or datetime.now(timezone.utc)
    open_ports = [r for r in port_results if r.open]
    finding_dicts = [f.to_dict() for f in findings]

    return {
        "target": target,
        "resolved_ip": resolved_ip,
        "scanned_at": scanned_at.isoformat(),
        "ports_scanned": len(port_results),
        "open_ports": [{"port": r.port, "banner": r.banner} for r in open_ports],
        "findings": finding_dicts,
        "summary": {
            "open_port_count": len(open_ports),
            "total_findings": len(finding_dicts),
            "highest_severity": scoring.highest_severity(finding_dicts),
            "risk_score": scoring.risk_score(finding_dicts),
        },
    }


def filter_by_min_severity(report: dict, minimum: str) -> dict:
    findings = [f for f in report["findings"] if scoring.meets_min_severity(f["severity"], minimum)]
    filtered = dict(report)
    filtered["findings"] = findings
    filtered["summary"] = dict(report["summary"])
    filtered["summary"]["total_findings"] = len(findings)
    filtered["summary"]["highest_severity"] = scoring.highest_severity(findings)
    filtered["summary"]["risk_score"] = scoring.risk_score(findings)
    return filtered


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def render_markdown(report: dict, narrative: str | None = None) -> str:
    summary = report["summary"]
    lines = [
        f"# Recon Report — {report['target']} ({report['resolved_ip']})",
        "",
        f"Scanned at: {report['scanned_at']}",
        "",
        f"Ports scanned: {report['ports_scanned']}  |  "
        f"Open: {summary['open_port_count']}  |  "
        f"Risk score: {summary['risk_score']}/100  |  "
        f"Highest severity: {summary['highest_severity'].upper()}",
        "",
        "## Open ports",
        "",
        "| Port | Banner |",
        "|---|---|",
    ]
    if report["open_ports"]:
        for p in report["open_ports"]:
            banner = p["banner"].replace("|", "\\|").replace("\n", " ") or "_(no banner)_"
            lines.append(f"| {p['port']} | {banner[:120]} |")
    else:
        lines.append("| _(none)_ | |")

    lines += ["", "## Findings", ""]
    if report["findings"]:
        lines += ["| Severity | Port | Title | Recommendation |", "|---|---|---|---|"]
        ordered = sorted(
            report["findings"],
            key=lambda f: scoring.SEVERITY_ORDER.index(f["severity"]),
            reverse=True,
        )
        for f in ordered:
            lines.append(
                f"| {f['severity'].upper()} | {f['port']} | {f['title']} | {f['recommendation']} |"
            )
    else:
        lines.append("No findings.")

    if narrative:
        lines += ["", "## Analyst Narrative", "", narrative]

    return "\n".join(lines)
