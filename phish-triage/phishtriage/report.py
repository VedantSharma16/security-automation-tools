from __future__ import annotations

import json

from .models import ParsedEmail, Verdict


def to_json(p: ParsedEmail, v: Verdict) -> str:
    return json.dumps({"subject": p.subject, "from": p.from_addr, **v.to_dict()}, indent=2)


def to_text(p: ParsedEmail, v: Verdict) -> str:
    lines = [
        f"Subject : {p.subject}",
        f"From    : {p.from_display} <{p.from_addr}>",
        f"Verdict : {v.label} (score {v.score}/100)",
        "",
    ]
    if not v.findings:
        lines.append("No indicators found.")
    for f in v.findings:
        lines.append(f"[{f.severity.upper():8}] {f.rule} - {f.description}")
        if f.evidence:
            lines.append(f"           evidence: {f.evidence}")
        if f.mitre:
            lines.append(f"           ATT&CK:   {f.mitre}")
    urls = sorted({u.host for u in p.urls if u.host})
    if urls:
        lines += ["", "Extracted domains (defanged): " + ", ".join(d.replace(".", "[.]") for d in urls)]
    return "\n".join(lines)
