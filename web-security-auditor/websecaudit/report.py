"""Console, JSON, and Markdown rendering of a ScanResult."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .findings import SEVERITY_RANK
from .scanner import ScanResult

_SEVERITY_COLOR = {
    "info": "\033[90m",       # gray
    "low": "\033[36m",        # cyan
    "medium": "\033[33m",     # yellow
    "high": "\033[31m",       # red
    "critical": "\033[1;31m",  # bold red
}
_GRADE_COLOR = {
    "A+": "\033[1;32m", "A": "\033[32m", "B": "\033[36m",
    "C": "\033[33m", "D": "\033[31m", "F": "\033[1;31m",
}
_RESET = "\033[0m"


def build_report(result: ScanResult) -> dict:
    fr = result.fetch
    severity_counts = {s: 0 for s in SEVERITY_RANK}
    for f in result.findings:
        severity_counts[f.severity] += 1

    return {
        "scanned_at": datetime.now(tz=timezone.utc).isoformat(),
        "requested_url": fr.requested_url,
        "final_url": fr.final_url,
        "status_code": fr.status_code,
        "scheme": fr.scheme,
        "redirect_chain": [{"url": u, "status_code": s} for u, s in fr.redirect_chain],
        "tls": _tls_dict(fr.tls),
        "score": result.score,
        "grade": result.grade,
        "finding_count": len(result.findings),
        "severity_counts": severity_counts,
        "findings": [f.as_dict() for f in result.findings],
        "error": fr.error,
    }


def _tls_dict(tls) -> dict | None:
    if tls is None:
        return None
    return {
        "protocol_version": tls.protocol_version,
        "cipher": tls.cipher,
        "not_after": tls.not_after.isoformat() if tls.not_after else None,
        "days_until_expiry": tls.days_until_expiry,
        "error": tls.error,
    }


def render_console(report: dict, use_color: bool = True) -> str:
    lines = []
    grade_color = _GRADE_COLOR.get(report["grade"], "") if use_color else ""
    reset = _RESET if use_color else ""

    lines.append(f"web-security-auditor — {report['requested_url']}")
    if report["final_url"] != report["requested_url"]:
        lines.append(f"  -> redirected to {report['final_url']}")
    lines.append(f"Status: {report['status_code']}   Scheme: {report['scheme']}")
    lines.append(f"Grade: {grade_color}{report['grade']}{reset}   Score: {report['score']}/100")
    lines.append(f"Findings: {report['finding_count']}")

    if report["error"]:
        lines.append(f"Error: {report['error']}")
        return "\n".join(lines)

    if not report["findings"]:
        lines.append("No issues found. ✅")
    else:
        lines.append("")
        for f in report["findings"]:
            color = _SEVERITY_COLOR.get(f["severity"], "") if use_color else ""
            lines.append(f"{color}[{f['severity'].upper():8}]{reset} {f['id']} ({f['category']})")
            lines.append(f"           {f['message']}")
            lines.append(f"           -> {f['recommendation']}")

    tls = report.get("tls")
    if tls:
        lines.append("")
        lines.append(
            f"TLS: {tls['protocol_version']}  cipher={tls['cipher']}  "
            f"expires_in_days={tls['days_until_expiry']}"
        )

    return "\n".join(lines)


def render_markdown(report: dict) -> str:
    lines = [
        f"# Web Security Audit — {report['requested_url']}",
        "",
        f"- **Scanned at:** {report['scanned_at']}",
        f"- **Final URL:** {report['final_url']}",
        f"- **Status code:** {report['status_code']}",
        f"- **Grade:** {report['grade']} ({report['score']}/100)",
        f"- **Findings:** {report['finding_count']}",
        "",
    ]
    if report["error"]:
        lines.append(f"**Error:** {report['error']}")
        return "\n".join(lines)

    if report["findings"]:
        lines.append("| Severity | ID | Category | Message | Recommendation |")
        lines.append("|---|---|---|---|---|")
        for f in report["findings"]:
            lines.append(
                f"| {f['severity']} | `{f['id']}` | {f['category']} | "
                f"{f['message']} | {f['recommendation']} |"
            )
    else:
        lines.append("No issues found.")

    tls = report.get("tls")
    if tls:
        lines.append("")
        lines.append("## TLS")
        lines.append(f"- Protocol: {tls['protocol_version']}")
        lines.append(f"- Cipher: {tls['cipher']}")
        lines.append(f"- Days until certificate expiry: {tls['days_until_expiry']}")

    return "\n".join(lines)


def write_json(report: dict, path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)


def write_markdown(report: dict, path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_markdown(report))
