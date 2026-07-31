"""Render an ``AuditResult`` as human-readable text or machine-readable JSON."""

from __future__ import annotations

import dataclasses
import json
from typing import List

from .auditor import AuditResult
from .models import Severity, Status

_STATUS_MARKS = {
    Status.PASS: "[PASS]",
    Status.WARN: "[WARN]",
    Status.FAIL: "[FAIL]",
}

_SEVERITY_ORDER = {sev: i for i, sev in enumerate(Severity.ORDER)}


def render_text(result: AuditResult) -> str:
    lines: List[str] = []
    lines.append(f"Target:   {result.url}")
    if result.fetch_result.final_url != result.url:
        lines.append(f"Resolved: {result.fetch_result.final_url}")

    if result.fetch_result.ok:
        lines.append(f"Status:   HTTP {result.fetch_result.status} ({result.fetch_result.elapsed_ms:.0f} ms)")
    else:
        lines.append(f"Status:   unreachable ({result.fetch_result.error})")

    if result.tls_info is not None:
        if result.tls_info.ok:
            lines.append(
                f"TLS:      {result.tls_info.protocol}, {result.tls_info.cipher}, "
                f"expires in {result.tls_info.days_until_expiry}d ({result.tls_info.not_after})"
            )
        else:
            lines.append(f"TLS:      error ({result.tls_info.error})")

    lines.append(f"Grade:    {result.grade}  (score {result.score}/100)")
    lines.append("")
    lines.append("Findings:")

    ordered = sorted(result.findings, key=lambda f: (f.status != Status.FAIL, f.status != Status.WARN, _SEVERITY_ORDER.get(f.severity, 99)))
    for finding in ordered:
        mark = _STATUS_MARKS.get(finding.status, "[----]")
        lines.append(f"  {mark} [{finding.severity.upper():<8}] {finding.title}: {finding.message}")
        if finding.status != Status.PASS and finding.remediation:
            lines.append(f"           -> {finding.remediation}")

    return "\n".join(lines)


def render_json(result: AuditResult) -> str:
    payload = {
        "url": result.url,
        "score": result.score,
        "grade": result.grade,
        "http": dataclasses.asdict(result.fetch_result),
        "tls": dataclasses.asdict(result.tls_info) if result.tls_info is not None else None,
        "findings": [f.to_dict() for f in result.findings],
    }
    return json.dumps(payload, indent=2)
