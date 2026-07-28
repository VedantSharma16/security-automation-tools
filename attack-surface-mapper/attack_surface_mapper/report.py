"""Rendering HostReports as colored console output or structured JSON."""

from __future__ import annotations

import json
from dataclasses import asdict

from .models import HostReport

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SEVERITY_COLOR = {
    "info": "\033[37m",       # gray
    "low": "\033[36m",        # cyan
    "medium": "\033[33m",     # yellow
    "high": "\033[31m",       # red
    "critical": "\033[1;31m",  # bold red
}
_RESET = "\033[0m"


def to_dict(reports: list[HostReport]) -> list[dict]:
    return [asdict(r) for r in reports]


def write_json(reports: list[HostReport], path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(to_dict(reports), fh, indent=2)


def render_console(report: HostReport, use_color: bool = True) -> str:
    lines = []
    color = _SEVERITY_COLOR.get(report.risk_level, "") if use_color else ""
    reset = _RESET if use_color else ""

    ip_suffix = f" ({report.ip})" if report.ip else ""
    lines.append(f"{color}[{report.risk_level.upper():8}]{reset} {report.host}{ip_suffix}")
    lines.append(f"           risk score: {report.risk_score}/100")

    if report.errors:
        for err in report.errors:
            lines.append(f"           ! {err}")

    if report.open_ports:
        port_list = ", ".join(
            f"{p.port}/{p.service}" + ("*" if p.sensitive else "") for p in report.open_ports
        )
        lines.append(f"           open ports: {port_list}")

    findings_sorted = sorted(
        report.findings, key=lambda f: _SEVERITY_RANK.get(f.severity, 0), reverse=True
    )
    for finding in findings_sorted:
        fcolor = _SEVERITY_COLOR.get(finding.severity, "") if use_color else ""
        lines.append(f"           {fcolor}[{finding.severity:8}]{reset} {finding.title}")
        lines.append(f"                      {finding.detail}")

    if not report.open_ports and not report.findings and not report.errors:
        lines.append("           no exposures detected ✅")

    return "\n".join(lines)


def render_summary(reports: list[HostReport], use_color: bool = True) -> str:
    sections = [render_console(r, use_color=use_color) for r in reports]
    header = (
        f"Attack Surface Mapper — {len(reports)} host(s) scanned "
        "(* = sensitive service exposed externally)"
    )
    return "\n\n".join([header, *sections])
