"""Alert summaries and MITRE ATT&CK coverage reporting."""
from __future__ import annotations

from collections import Counter

from .engine import Alert
from .rules import LEVELS, Rule


def summarize(alerts: list[Alert]) -> dict:
    by_level = Counter(a.level for a in alerts)
    techniques = Counter(t for a in alerts for t in a.techniques)
    return {
        "total_alerts": len(alerts),
        "by_level": {lvl: by_level[lvl] for lvl in reversed(LEVELS) if by_level[lvl]},
        "techniques_observed": dict(sorted(techniques.items())),
    }


def coverage(rules: list[Rule]) -> dict:
    """Which ATT&CK techniques/tactics the rule set covers, and which rules lack mapping."""
    tech: dict[str, list[str]] = {}
    tactics: dict[str, int] = Counter()
    unmapped = []
    for r in rules:
        if not r.techniques:
            unmapped.append(r.id)
        for t in r.techniques:
            tech.setdefault(t, []).append(r.id)
        for t in r.tactics:
            tactics[t] += 1
    return {
        "rules": len(rules),
        "techniques": dict(sorted(tech.items())),
        "tactics": dict(sorted(tactics.items())),
        "unmapped_rules": unmapped,
    }


def format_text(alerts: list[Alert]) -> str:
    if not alerts:
        return "No detections.\n"
    order = {lvl: i for i, lvl in enumerate(reversed(LEVELS))}
    lines = []
    for a in sorted(alerts, key=lambda a: order[a.level]):
        tech = f" [{', '.join(a.techniques)}]" if a.techniques else ""
        grp = f" group={a.group}" if a.group else ""
        lines.append(f"[{a.level.upper():<8}] {a.title}{tech} ({a.event_count} event(s){grp})")
    s = summarize(alerts)
    lines.append(f"\n{s['total_alerts']} alert(s): " + ", ".join(f"{k}={v}" for k, v in s["by_level"].items()))
    return "\n".join(lines) + "\n"
