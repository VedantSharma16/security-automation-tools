"""Render a pipeline result dict as JSON or Markdown."""

from __future__ import annotations

import json


def to_json(result: dict) -> str:
    return json.dumps(result, indent=2)


def to_markdown(result: dict) -> str:
    lines: list[str] = []
    lines.append(f"# Web Recon Report: {result['target']}")
    lines.append("")
    lines.append(f"Generated: {result['generated_at']}")
    lines.append(f"HTTP status: {result['http']['status_code']} ({result['http']['elapsed_ms']} ms)")
    lines.append("")

    if result["http"]["error"]:
        lines.append(f"**Target unreachable:** {result['http']['error']}")
        return "\n".join(lines) + "\n"

    lines.append("## Risk Summary")
    lines.append("")
    lines.append(f"- Overall risk score: {result['risk_score']}/100 ({result['risk_grade']})")
    lines.append(f"- Security header grade: {result['security_headers']['grade']} ({result['security_headers']['score']}/100)")
    lines.append("")

    lines.append("## Security Header Findings")
    lines.append("")
    if result["security_headers"]["findings"]:
        for f in result["security_headers"]["findings"]:
            lines.append(f"- [{f['severity']}] **{f['header']}**: {f['message']}")
    else:
        lines.append("No issues found.")
    lines.append("")

    if result["tls"]:
        lines.append("## TLS")
        lines.append("")
        tls = result["tls"]
        lines.append(f"- Host: {tls['host']}")
        lines.append(f"- Protocol: {tls['protocol_version'] or 'unknown'}")
        lines.append(f"- Issuer: {tls['issuer'] or 'unknown'}")
        lines.append(f"- Expires: {tls['not_after'] or 'unknown'}"
                      + (f" ({tls['days_until_expiry']} day(s) remaining)" if tls['days_until_expiry'] is not None else ""))
        if result["tls_findings"]:
            lines.append("")
            for f in result["tls_findings"]:
                lines.append(f"- [{f['severity']}] {f['message']}")
        lines.append("")

    lines.append("## Fingerprinted Technologies")
    lines.append("")
    if result["technologies"]:
        for t in result["technologies"]:
            lines.append(f"- **{t['name']}** ({t['category']})")
    else:
        lines.append("None identified.")
    lines.append("")

    if result.get("narrative"):
        lines.append("## Analyst Narrative")
        lines.append("")
        lines.append(result["narrative"])
        lines.append("")

    return "\n".join(lines)
