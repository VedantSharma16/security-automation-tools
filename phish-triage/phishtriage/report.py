"""Render analysis results as text, JSON, or an IOC list."""
from __future__ import annotations

import json
from urllib.parse import urlparse

from .detectors import _host
from .models import ParsedEmail, Finding

ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def extract_iocs(p: ParsedEmail) -> dict:
    urls = sorted({l.href for l in p.links})
    domains = sorted({h for h in (_host(u) for u in urls) if h})
    return {
        "urls": urls,
        "domains": domains,
        "sender": p.from_addr,
        "reply_to": p.reply_to,
        "attachment_sha256": sorted({a.sha256 for a in p.attachments}),
    }


def to_dict(p: ParsedEmail, findings: list[Finding], risk: int, verdict: str) -> dict:
    return {
        "verdict": verdict,
        "risk_score": risk,
        "subject": p.subject,
        "from": p.from_addr,
        "authentication": p.auth,
        "findings": [f.to_dict() for f in sorted(findings, key=lambda f: ORDER[f.severity])],
        "iocs": extract_iocs(p),
    }


def render_json(*args) -> str:
    return json.dumps(to_dict(*args), indent=2)


def render_text(p: ParsedEmail, findings: list[Finding], risk: int, verdict: str) -> str:
    lines = [
        f"Verdict: {verdict.upper()}  (risk {risk}/100)",
        f"Subject: {p.subject}",
        f"From:    {p.from_name} <{p.from_addr}>",
        f"Auth:    " + (", ".join(f"{k}={v}" for k, v in p.auth.items()) or "n/a"),
        "",
        f"Findings ({len(findings)}):",
    ]
    for f in sorted(findings, key=lambda f: ORDER[f.severity]):
        mitre = f" [{f.mitre}]" if f.mitre else ""
        lines.append(f"  [{f.severity.upper():8}] {f.title}{mitre}")
        lines.append(f"             {f.detail}")
    if not findings:
        lines.append("  none")
    iocs = extract_iocs(p)
    lines += ["", "IOCs:"]
    for k in ("domains", "urls", "attachment_sha256"):
        for v in iocs[k]:
            lines.append(f"  {k[:-1] if k.endswith('s') else k}: {v}")
    return "\n".join(lines)
