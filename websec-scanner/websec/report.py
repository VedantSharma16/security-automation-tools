"""Console, JSON, and Markdown rendering of a ScanResult."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .models import SEVERITY_RANK, Severity

_SEVERITY_COLOR = {
    Severity.INFO: "\033[37m",       # white
    Severity.LOW: "\033[36m",        # cyan
    Severity.MEDIUM: "\033[33m",     # yellow
    Severity.HIGH: "\033[31m",       # red
    Severity.CRITICAL: "\033[1;31m",  # bold red
}
_RESET = "\033[0m"


def _sorted_findings(result):
    return sorted(result.findings, key=lambda f: SEVERITY_RANK[f.severity], reverse=True)


def to_dict(result) -> dict:
    return {
        "target": result.target,
        "duration_seconds": round(result.finished_at - result.started_at, 3),
        "active_checks_run": result.active_checks_run,
        "pages_crawled": result.pages_crawled,
        "endpoints_tested": result.endpoints_tested,
        "finding_count": len(result.findings),
        "highest_severity": result.highest_severity.value if result.highest_severity else None,
        "findings": [f.to_dict() for f in _sorted_findings(result)],
    }


def to_json(result) -> str:
    return json.dumps(to_dict(result), indent=2)


def to_markdown(result) -> str:
    data = to_dict(result)
    lines = [
        f"# Web Security Scan Report",
        "",
        f"- **Target:** {data['target']}",
        f"- **Scanned:** {datetime.now(timezone.utc).isoformat()}",
        f"- **Duration:** {data['duration_seconds']}s",
        f"- **Active checks run:** {data['active_checks_run']}",
        f"- **Pages crawled / endpoints tested:** {data['pages_crawled']} / {data['endpoints_tested']}",
        f"- **Findings:** {data['finding_count']} (highest severity: {data['highest_severity'] or 'none'})",
        "",
        "## Findings",
        "",
    ]
    if not data["findings"]:
        lines.append("No findings.")
    for f in data["findings"]:
        lines.append(f"### [{f['severity'].upper()}] {f['title']}")
        lines.append("")
        lines.append(f"- **Check:** {f['check']}")
        lines.append(f"- **URL:** {f['url']}")
        if f["detail"]:
            lines.append(f"- **Detail:** {f['detail']}")
        if f["evidence"]:
            lines.append(f"- **Evidence:** `{f['evidence']}`")
        if f["recommendation"]:
            lines.append(f"- **Recommendation:** {f['recommendation']}")
        lines.append("")
    return "\n".join(lines)


def to_console(result, use_color: bool = True) -> str:
    data = to_dict(result)
    lines = [
        f"Target: {data['target']}",
        f"Duration: {data['duration_seconds']}s  |  Active checks: {data['active_checks_run']}  |  "
        f"Pages crawled: {data['pages_crawled']}  |  Endpoints tested: {data['endpoints_tested']}",
        f"Findings: {data['finding_count']} (highest: {data['highest_severity'] or 'none'})",
        "-" * 70,
    ]
    for f in _sorted_findings(result):
        color = _SEVERITY_COLOR[f.severity] if use_color else ""
        reset = _RESET if use_color else ""
        lines.append(f"{color}[{f.severity.value.upper():>8}]{reset} {f.title}")
        lines.append(f"           url: {f.url}")
        if f.detail:
            lines.append(f"           {f.detail}")
        if f.recommendation:
            lines.append(f"           fix: {f.recommendation}")
        lines.append("")
    if not result.findings:
        lines.append("No findings.")
    return "\n".join(lines)
