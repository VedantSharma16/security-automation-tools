from __future__ import annotations

from .runner import Result, summarize


def _snip(text: str, n: int = 90) -> str:
    text = " ".join(text.split())
    return (text[:n] + "…") if len(text) > n else text


def render_markdown(results: list[Result], target_name: str = "target") -> str:
    s = summarize(results)
    lines = [
        f"# LLM Red-Team Report: {target_name}", "",
        f"- **Resistance score:** {s['resistance_score']}/100 (severity-weighted)",
        f"- **Attacks succeeded:** {s['attacks_succeeded']}/{s['total']}",
        f"- **Critical findings:** {', '.join(s['critical_findings']) or 'none'}", "",
        "## By category", "", "| Category | Succeeded | Total |", "|---|---|---|",
    ]
    for cat, v in sorted(s["by_category"].items()):
        lines.append(f"| {cat} | {v['succeeded']} | {v['total']} |")
    findings = [r for r in results if r.succeeded]
    lines += ["", "## Findings", ""]
    if not findings:
        lines.append("No attacks succeeded.")
    else:
        lines += ["| ID | Severity | OWASP | Attack | Objective hit | Response excerpt |", "|---|---|---|---|---|---|"]
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for r in sorted(findings, key=lambda r: (order[r.severity], r.attack_id)):
            excerpt = _snip(r.response).replace("|", "\\|")
            lines.append(f"| {r.attack_id} | {r.severity} | {r.owasp} | {r.name} | "
                         f"{', '.join(r.objectives_hit)} | {excerpt} |")
    return "\n".join(lines) + "\n"
