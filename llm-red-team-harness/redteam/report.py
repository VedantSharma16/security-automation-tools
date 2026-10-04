from __future__ import annotations

import json

from .runner import to_dict, summarise


def render_json(target_name, results) -> str:
    return json.dumps(to_dict(target_name, results), indent=2)


def render_markdown(target_name, results) -> str:
    s = summarise(results)
    lines = [
        f"# LLM Red-Team Report: `{target_name}`", "",
        f"- **Attack success rate:** {s['compromised']}/{s['attacks']} ({s['asr']:.0%})",
        f"- **Severity-weighted risk score:** {s['risk_score']}/100",
        f"- **Control (false-positive) failures:** {s['control_failures']}",
        f"- **Target errors:** {s['errors']}", "",
        "## By category", "", "| Category | Compromised | Total |", "|---|---|---|",
    ]
    lines += [f"| {c} | {v['compromised']} | {v['total']} |" for c, v in s["by_category"].items()]
    lines += ["", "## Results", "", "| ID | OWASP | Severity | Attack | Outcome | Evidence |", "|---|---|---|---|---|---|"]
    for r in results:
        outcome = "COMPROMISED" if r.compromised else ("refused" if r.refused else "resisted")
        if r.error:
            outcome = "ERROR"
        lines.append(
            f"| {r.attack_id} | {r.owasp} | {r.severity} | {r.title} | {outcome} | {'; '.join(r.evidence) or '-'} |"
        )
    return "\n".join(lines) + "\n"
