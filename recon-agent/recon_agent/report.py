"""Assemble and render the final recon report."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .agent import ReconRun
from .findings import Finding, overall_risk

SEVERITY_COLOR = {
    "critical": "\033[91m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[94m",
    "info": "\033[92m",
}
RESET = "\033[0m"
SEVERITY_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "🟢"}


def build_report(run: ReconRun, findings: list[Finding]) -> dict:
    return {
        "target": run.target,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "ip": run.ip,
        "subdomains": run.subdomains,
        "open_ports": [asdict(p) for p in run.open_ports],
        "http_fingerprints": [asdict(fp) for fp in run.http_fingerprints],
        "tool_calls_made": run.tool_calls_made,
        "overall_risk": overall_risk(findings),
        "findings": [f.to_dict() for f in findings],
        "agent_narrative": run.agent_narrative,
    }


def render_console(report: dict, *, use_color: bool = True) -> str:
    def colorize(severity: str, text: str) -> str:
        if not use_color:
            return text
        return f"{SEVERITY_COLOR.get(severity, '')}{text}{RESET}"

    risk = report["overall_risk"]
    lines = [
        colorize(risk, f"{SEVERITY_ICON.get(risk, '')} Overall risk: {risk.upper()}"),
        f"Target: {report['target']}  ({report['ip'] or 'unresolved'})",
        f"Tool calls: {', '.join(report['tool_calls_made']) or 'none'}",
        "",
    ]

    if report["subdomains"]:
        lines.append(f"Subdomains ({len(report['subdomains'])}):")
        for name, ip in sorted(report["subdomains"].items()):
            lines.append(f"  - {name} -> {ip}")
        lines.append("")

    if report["open_ports"]:
        lines.append(f"Open ports ({len(report['open_ports'])}):")
        for port in report["open_ports"]:
            lines.append(f"  - {port['port']}/tcp ({port['service']})")
        lines.append("")

    if report["findings"]:
        lines.append(f"Findings ({len(report['findings'])}):")
        for finding in report["findings"]:
            lines.append(
                colorize(
                    finding["severity"],
                    f"  [{finding['severity'].upper()}] {finding['category']} @ "
                    f"{finding['target']}: {finding['detail']}",
                )
            )
        lines.append("")
    else:
        lines.append("No findings.")
        lines.append("")

    if report["agent_narrative"]:
        lines.append("Analyst narrative:")
        lines.append(report["agent_narrative"])

    return "\n".join(lines)


def write_json(report: dict, path: Path) -> None:
    path.write_text(json.dumps(report, indent=2, default=str))
