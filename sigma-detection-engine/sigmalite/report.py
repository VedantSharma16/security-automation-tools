"""Render scan results as Markdown or JSON."""

from __future__ import annotations

import json
from collections import Counter
from typing import Iterable

from .correlate import Incident
from .engine import Alert
from .rule import LEVELS

_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "informational": "⚪"}


def to_json(alerts: list[Alert], incidents: list[Incident], events_scanned: int, rules_loaded: int) -> str:
    return json.dumps({
        "summary": {
            "events_scanned": events_scanned,
            "rules_loaded": rules_loaded,
            "alerts": len(alerts),
            "incidents": len(incidents),
            "by_level": dict(Counter(a.level for a in alerts)),
        },
        "incidents": [i.to_dict() for i in incidents],
        "alerts": [a.to_dict() for a in alerts],
    }, indent=2, default=str)


def to_markdown(alerts: list[Alert], incidents: Iterable[Incident], events_scanned: int, rules_loaded: int) -> str:
    incidents = list(incidents)
    counts = Counter(a.level for a in alerts)
    lines = [
        "# Detection Report",
        "",
        f"Scanned **{events_scanned}** events with **{rules_loaded}** rules → "
        f"**{len(alerts)}** alerts in **{len(incidents)}** incident(s).",
        "",
        " · ".join(f"{_ICON[l]} {l}: {counts[l]}" for l in reversed(LEVELS) if counts[l]) or "No alerts.",
    ]
    if incidents:
        lines += ["", "## Incidents", ""]
        for n, inc in enumerate(incidents, 1):
            window = f"{inc.start:%Y-%m-%d %H:%M:%S} → {inc.end:%H:%M:%S} UTC" if inc.start else "time unknown"
            flag = " — **multi-stage, escalated**" if inc.multi_stage else ""
            lines += [
                f"### {n}. {_ICON[inc.level]} {inc.level.upper()} · `{inc.host}`{flag}",
                "",
                f"- **Window:** {window}",
                f"- **Kill chain:** {inc.kill_chain}",
                f"- **Techniques:** {', '.join(inc.techniques) or '—'}",
                "",
                "| Time | Level | Rule | Detail |",
                "|---|---|---|---|",
            ]
            for a in inc.alerts:
                ctx = a.context
                dest = f"{ctx['DestinationIp']}:{ctx.get('DestinationPort', '?')}" if "DestinationIp" in ctx else ""
                detail = ctx.get("CommandLine") or ctx.get("TargetObject") or \
                    (f"{ctx.get('Image', '')} → {dest}" if dest else ctx.get("Image", ""))
                detail = str(detail).replace("|", "\\|")
                if len(detail) > 90:
                    detail = detail[:87] + "..."
                lines.append(f"| {a.timestamp or '—'} | {a.level} | {a.rule_title} | `{detail}` |")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"
