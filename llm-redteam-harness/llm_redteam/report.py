"""Report generation: JSON, Markdown."""

from __future__ import annotations

from collections import defaultdict

from llm_redteam.runner import Result, resistance_score


def by_category(results: list[Result]) -> dict[str, dict[str, int]]:
    cats: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "vulnerable": 0, "error": 0})
    for r in results:
        c = cats[r.attack.category]
        c["total"] += 1
        c["vulnerable"] += r.verdict == "VULNERABLE"
        c["error"] += r.verdict == "ERROR"
    return dict(cats)


def to_dict(results: list[Result], target_name: str) -> dict:
    return {
        "target": target_name,
        "resistance_score": resistance_score(results),
        "total": len(results),
        "vulnerable": sum(r.verdict == "VULNERABLE" for r in results),
        "categories": by_category(results),
        "results": [
            {
                "id": r.attack.id,
                "title": r.attack.title,
                "category": r.attack.category,
                "owasp": r.attack.owasp,
                "severity": r.attack.severity,
                "verdict": r.verdict,
                "reasons": r.reasons,
                "response_excerpt": r.response[:300],
            }
            for r in results
        ],
    }


def to_markdown(results: list[Result], target_name: str) -> str:
    d = to_dict(results, target_name)
    lines = [
        f"# LLM Red-Team Report: `{target_name}`",
        "",
        f"**Resistance score:** {d['resistance_score']}/100  ",
        f"**Vulnerable:** {d['vulnerable']} of {d['total']} attacks",
        "",
        "| Category | Attacks | Vulnerable |",
        "|---|---|---|",
    ]
    for cat, c in sorted(d["categories"].items()):
        lines.append(f"| {cat} | {c['total']} | {c['vulnerable']} |")
    lines += ["", "## Findings", "", "| ID | OWASP | Severity | Verdict | Detail |", "|---|---|---|---|---|"]
    order = {"VULNERABLE": 0, "ERROR": 1, "RESISTED": 2}
    for r in sorted(results, key=lambda r: (order[r.verdict], r.attack.id)):
        detail = "; ".join(r.reasons) or "-"
        lines.append(f"| {r.attack.id} {r.attack.title} | {r.attack.owasp} | {r.attack.severity} | {r.verdict} | {detail} |")
    return "\n".join(lines) + "\n"
