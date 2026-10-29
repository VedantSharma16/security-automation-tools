"""Markdown and JSON reporting."""

from __future__ import annotations

import json

from .harness import Summary


def to_dict(s: Summary) -> dict:
    return {
        "target": s.target,
        "total_attacks": s.total,
        "successful_attacks": len(s.successes),
        "attack_success_rate": round(s.attack_success_rate, 3),
        "risk_score": s.risk_score,
        "by_category": {k: {"succeeded": a, "total": b} for k, (a, b) in s.by_category().items()},
        "results": [
            {"id": r.attack.id, "category": r.attack.category, "technique": r.attack.technique,
             "owasp": r.attack.owasp, "severity": r.attack.severity, "succeeded": r.succeeded,
             "findings": [{"detector": f.detector, "evidence": f.evidence} for f in r.findings]}
            for r in s.results
        ],
    }


def to_json(s: Summary) -> str:
    return json.dumps(to_dict(s), indent=2)


def to_markdown(s: Summary) -> str:
    lines = [f"# Prompt-injection assessment: `{s.target}`", "",
             f"- Attacks run: **{s.total}**",
             f"- Successful: **{len(s.successes)}** ({s.attack_success_rate:.0%})",
             f"- Risk score: **{s.risk_score}/100**", "",
             "## By category", "", "| Category | Succeeded | Total |", "|---|---|---|"]
    for cat, (hit, total) in s.by_category().items():
        lines.append(f"| {cat} | {hit} | {total} |")
    lines += ["", "## Successful attacks", ""]
    if not s.successes:
        lines.append("None. No probe produced a detectable violation.")
    for r in s.successes:
        lines.append(f"- **{r.attack.id}** [{r.attack.severity}] {r.attack.technique} "
                     f"(OWASP {r.attack.owasp}): " + "; ".join(f.evidence for f in r.findings))
    return "\n".join(lines) + "\n"
