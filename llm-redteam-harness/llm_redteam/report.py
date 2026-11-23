"""Markdown / console reporting, including a baseline-vs-guarded comparison."""

from __future__ import annotations

from .probes import OWASP_LLM_TOP10
from .runner import RunResult


def _pct(x: float) -> str:
    return f"{x * 100:.0f}%"


def render_markdown(run: RunResult) -> str:
    s = run.summary()
    lines = [
        f"# LLM red-team report — `{s['target']}`",
        "",
        f"- **Attack success rate:** {_pct(s['attack_success_rate'])} "
        f"({s['successful_attacks']}/{s['attacks']} probes)",
    ]
    if s["benign_prompts"]:
        lines.append(f"- **Guardrail false-positive rate:** {_pct(s['guardrail_false_positive_rate'])} "
                     f"on {s['benign_prompts']} benign prompts")
    lines += ["", "## By OWASP LLM Top 10 category", "", "| ID | Risk | Probes | Successful | ASR |", "|---|---|---|---|---|"]
    for key, row in s["by_owasp"].items():
        lines.append(f"| {key} | {OWASP_LLM_TOP10.get(key, '')} | {row['total']} | {row['successful']} | {_pct(row['asr'])} |")
    lines += ["", "## By attack category", "", "| Category | Probes | Successful | ASR |", "|---|---|---|---|"]
    for key, row in s["by_category"].items():
        lines.append(f"| {key} | {row['total']} | {row['successful']} | {_pct(row['asr'])} |")

    lines += ["", "## Probe results", "", "| Probe | Technique | Result | Evidence / guardrail action |", "|---|---|---|---|"]
    for r in run.attacks:
        if r.error:
            status, detail = "ERROR", r.error
        elif r.success:
            status, detail = "**VULNERABLE**", "; ".join(r.evidence.values())
        else:
            status = "defended"
            detail = "; ".join(r.guardrail_notes) or "model did not comply"
        lines.append(f"| {r.probe_id} | {r.technique} | {status} | {detail.replace('|', '/')} |")

    flagged = [r for r in run.benign if r.intervened]
    if flagged:
        lines += ["", "## Guardrail false positives (benign prompts that were interfered with)", ""]
        lines += [f"- `{r.probe_id}` — {'; '.join(r.guardrail_notes)}" for r in flagged]
    return "\n".join(lines) + "\n"


def render_comparison(baseline: RunResult, guarded: RunResult) -> str:
    b, g = baseline.summary(), guarded.summary()
    lines = [
        "# Guardrail effectiveness: baseline vs guarded",
        "",
        "| Metric | Baseline | Guarded |",
        "|---|---|---|",
        f"| Attack success rate | {_pct(b['attack_success_rate'])} | {_pct(g['attack_success_rate'])} |",
        f"| Successful attacks | {b['successful_attacks']}/{b['attacks']} | {g['successful_attacks']}/{g['attacks']} |",
        f"| False-positive rate (benign) | {_pct(b['guardrail_false_positive_rate'])} | {_pct(g['guardrail_false_positive_rate'])} |",
        "",
        "| OWASP | Baseline ASR | Guarded ASR |",
        "|---|---|---|",
    ]
    for key in sorted(set(b["by_owasp"]) | set(g["by_owasp"])):
        lines.append(f"| {key} {OWASP_LLM_TOP10.get(key, '')} | {_pct(b['by_owasp'].get(key, {}).get('asr', 0))} "
                     f"| {_pct(g['by_owasp'].get(key, {}).get('asr', 0))} |")
    residual = [r for r in guarded.attacks if r.success]
    lines += ["", "## Residual risk (attacks that bypassed the guardrails)", ""]
    lines += [f"- `{r.probe_id}` {r.technique}: {'; '.join(r.evidence.values())}" for r in residual] or ["- none"]
    return "\n".join(lines) + "\n"


def render_ablation(results: dict[str, RunResult]) -> str:
    categories = sorted({r.category for run in results.values() for r in run.attacks})
    header = "| Configuration | Overall ASR | " + " | ".join(categories) + " | Benign FP |"
    lines = ["# Guardrail layer ablation", "", header, "|" + "---|" * (len(categories) + 3)]
    for label, run in results.items():
        by_cat = run.asr_by("category")
        cells = [_pct(by_cat.get(c, {}).get("asr", 0)) for c in categories]
        lines.append(f"| {label} | {_pct(run.attack_success_rate())} | " + " | ".join(cells)
                     + f" | {_pct(run.false_positive_rate())} |")
    return "\n".join(lines) + "\n"
