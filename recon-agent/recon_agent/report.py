"""Turning an AgentRunResult into console output, Markdown, and JSON reports."""

from __future__ import annotations

import json

from .agent import AgentRunResult
from .vuln_kb import SEVERITY_ORDER

_SEVERITY_COLOR = {
    "info": "\033[36m",        # cyan
    "low": "\033[36m",         # cyan
    "medium": "\033[33m",      # yellow
    "high": "\033[31m",        # red
    "critical": "\033[1;31m",  # bold red
}
_RESET = "\033[0m"


def _service_label(fp: dict) -> str:
    version = fp.get("version")
    return f"{fp['service']} {version}" if version else fp["service"]


def render_console(run: AgentRunResult, narrative: str | None = None, use_color: bool = True) -> str:
    color = _SEVERITY_COLOR.get(run.risk, "") if use_color else ""
    reset = _RESET if use_color else ""

    lines = [f"recon-agent — target {run.target}"]
    lines.append(f"Overall risk      : {color}{run.risk.upper()}{reset}")
    lines.append(f"Steps taken       : {run.steps_taken} ({'completed' if run.completed else 'step budget hit'})")
    lines.append(f"Open ports        : {', '.join(str(p) for p in run.open_ports) or '(none)'}")

    if run.fingerprints:
        lines.append("")
        lines.append("Fingerprints:")
        for port in sorted(run.fingerprints):
            fp = run.fingerprints[port]
            lines.append(f"  port {port:<5} {_service_label(fp)} (via {fp['source']})")

    if run.tls_info:
        lines.append("")
        lines.append("TLS certificates:")
        for port in sorted(run.tls_info):
            info = run.tls_info[port]
            if info.get("error"):
                lines.append(f"  port {port:<5} error: {info['error']}")
            else:
                expiry = info.get("days_until_expiry")
                expiry_note = f", expires in {expiry}d" if expiry is not None else ""
                lines.append(f"  port {port:<5} {info.get('protocol')} subject={info.get('subject')}{expiry_note}")

    if run.vuln_matches:
        lines.append("")
        lines.append("Potential known vulnerabilities:")
        sorted_matches = sorted(run.vuln_matches, key=lambda m: SEVERITY_ORDER.index(m.severity))
        for m in sorted_matches:
            c = _SEVERITY_COLOR.get(m.severity, "") if use_color else ""
            lines.append(f"  {c}[{m.severity.upper():8}]{reset} {m.cve} — port {m.port} {m.service} {m.version}")
            lines.append(f"             {m.description}")
    else:
        lines.append("")
        lines.append("No known-CVE matches for fingerprinted services.")

    if narrative:
        lines.append("")
        lines.append("Summary:")
        lines.append(f"  {narrative}")

    return "\n".join(lines)


def render_markdown(run: AgentRunResult, narrative: str | None = None) -> str:
    lines = [f"# Recon Report: {run.target}", ""]
    lines.append(f"- **Overall risk:** {run.risk.upper()}")
    lines.append(f"- **Steps taken:** {run.steps_taken} ({'completed' if run.completed else 'step budget hit'})")
    lines.append(f"- **Open ports:** {', '.join(str(p) for p in run.open_ports) or 'none'}")
    lines.append("")

    if narrative:
        lines += ["## Summary", "", narrative, ""]

    lines.append("## Fingerprints")
    lines.append("")
    if run.fingerprints:
        lines.append("| Port | Service | Version | Source |")
        lines.append("|---|---|---|---|")
        for port in sorted(run.fingerprints):
            fp = run.fingerprints[port]
            lines.append(f"| {port} | {fp['service']} | {fp.get('version') or '-'} | {fp['source']} |")
    else:
        lines.append("_No services fingerprinted._")
    lines.append("")

    lines.append("## TLS Certificates")
    lines.append("")
    if run.tls_info:
        for port in sorted(run.tls_info):
            info = run.tls_info[port]
            lines.append(f"### Port {port}")
            if info.get("error"):
                lines.append(f"- Error: {info['error']}")
            else:
                lines.append(f"- Protocol: {info.get('protocol')}")
                lines.append(f"- Cipher: {info.get('cipher')}")
                lines.append(f"- Subject: {info.get('subject') or 'unavailable (install `cryptography` for cert parsing)'}")
                lines.append(f"- Issuer: {info.get('issuer') or 'unavailable'}")
                if info.get("days_until_expiry") is not None:
                    lines.append(f"- Expires in: {info['days_until_expiry']} day(s)")
            lines.append("")
    else:
        lines.append("_No TLS ports inspected._")
        lines.append("")

    lines.append("## Potential Known Vulnerabilities")
    lines.append("")
    if run.vuln_matches:
        lines.append("| Severity | CVE | Port | Service | Description |")
        lines.append("|---|---|---|---|---|")
        for m in sorted(run.vuln_matches, key=lambda m: SEVERITY_ORDER.index(m.severity)):
            lines.append(f"| {m.severity.upper()} | {m.cve} | {m.port} | {m.service} {m.version} | {m.description} |")
    else:
        lines.append("_No known-CVE matches for fingerprinted services._")
    lines.append("")

    lines.append("## Agent Transcript")
    lines.append("")
    lines.append("| Step | Tool | Reason |")
    lines.append("|---|---|---|")
    for i, obs in enumerate(run.transcript, start=1):
        lines.append(f"| {i} | `{obs.action.tool}` | {obs.action.reason} |")

    return "\n".join(lines)


def write_json(run: AgentRunResult, path, narrative: str | None = None) -> None:
    payload = run.to_dict()
    if narrative:
        payload["narrative"] = narrative
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
