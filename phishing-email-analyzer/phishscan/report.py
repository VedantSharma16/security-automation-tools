from __future__ import annotations

import json


def to_json(result: dict) -> str:
    return json.dumps(result, indent=2)


def to_text(result: dict) -> str:
    lines = [
        f"Subject : {result['subject']}",
        f"From    : {result['from']}",
        f"Verdict : {result['label'].upper()} (score {result['score']}/100)",
        "",
    ]
    if not result["findings"]:
        lines.append("No indicators found.")
    for f in result["findings"]:
        tag = f" [{f['mitre']}]" if f.get("mitre") else ""
        lines.append(f"[{f['severity'].upper():6}] {f['description']}{tag}")
        if f["evidence"]:
            lines.append(f"         evidence: {f['evidence']}")
    if result["attachments"]:
        lines += ["", "Attachments:"]
        lines += [f"  {a['filename']} ({a['size']}B, {a['magic']}) sha256={a['sha256']}" for a in result["attachments"]]
    return "\n".join(lines)
