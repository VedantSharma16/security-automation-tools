from __future__ import annotations

import json

from .models import Verdict
from .parser import ParsedEmail


def to_json(email: ParsedEmail, v: Verdict) -> str:
    return json.dumps({"subject": email.subject, "from": email.from_addr, **v.to_dict()}, indent=2)


def to_markdown(email: ParsedEmail, v: Verdict) -> str:
    lines = [f"# Phishing Analysis: {v.label} ({v.score}/100)", "",
             f"- **Subject:** {email.subject}", f"- **From:** {email.from_name} <{email.from_addr}>",
             f"- **Links:** {len(email.links)}  **Attachments:** {len(email.attachments)}", ""]
    if not v.findings:
        lines.append("No indicators found.")
    else:
        lines += ["| Severity | Rule | Description | ATT&CK | Evidence |", "|---|---|---|---|---|"]
        for f in v.findings:
            ev = f.evidence.replace("|", "\\|")
            lines.append(f"| {f.severity} | {f.rule} | {f.description} | {f.attack or '-'} | `{ev}` |")
    return "\n".join(lines) + "\n"
