"""Human-readable renderings of scan and evaluation results."""

from __future__ import annotations

from .detector import ScanResult
from .harness import EvalReport


def _pct(x: float) -> str:
    return f"{100 * x:.0f}%"


def render_scan(result: ScanResult) -> str:
    lines = [
        f"verdict : {result.verdict.upper()}  (score {result.score}/100, source={result.source})",
        f"mapping : {result.owasp}",
    ]
    if result.signals:
        lines.append(f"signals : {', '.join(result.signals)}")
    for m in result.matches:
        lines.append(f"  [{m.rule_id}] {m.name} ({m.category}, w={m.weight})")
        lines.append(f"      {m.excerpt}")
    if not result.matches and not result.signals:
        lines.append("no injection indicators found")
    return "\n".join(lines)


def render_eval_markdown(report: EvalReport) -> str:
    s, d = report.summary, report.detector
    out = [
        "# Prompt-injection red-team evaluation",
        "",
        f"- **Target:** `{report.target}`",
        f"- **Policy:** {'strict (quarantine on flag)' if report.strict else 'default (quarantine on block)'}",
        f"- **Attacks:** {s['attacks']} ({s['errors']} errored)",
        "",
        "## Attack success rate",
        "",
        "| | Unguarded | Guarded |",
        "|---|---:|---:|",
        f"| **Overall ASR** | {_pct(s['unguarded_asr'])} | {_pct(s['guarded_asr'])} |",
        "",
        f"Guard layers reduced successful attacks by **{_pct(s['asr_reduction'])}**. "
        f"Layer that stopped each attack: "
        + (", ".join(f"{k} = {v}" for k, v in s["stopped_by_layer"].items()) or "none")
        + ".",
        "",
        "| Technique | n | Detected | Unguarded ASR | Guarded ASR |",
        "|---|---:|---:|---:|---:|",
    ]
    for technique, row in report.by_technique.items():
        out.append(
            f"| {technique} | {row['n']} | {row['detected']}/{row['n']} | "
            f"{_pct(row['unguarded_asr'])} | {_pct(row['guarded_asr'])} |"
        )
    out += [
        "",
        "## Input detector (attacks vs. benign look-alikes)",
        "",
        "| Precision | Recall | F1 | False-block rate | TP | FP | TN | FN |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|",
        f"| {d['precision']:.2f} | {d['recall']:.2f} | {d['f1']:.2f} | {_pct(d['false_block_rate'])} "
        f"| {d['tp']} | {d['fp']} | {d['tn']} | {d['fn']} |",
        "",
        f"- Missed by the detector: {', '.join(d['missed']) or 'none'}",
        f"- Benign samples flagged: {', '.join(d['false_positives']) or 'none'}",
        f"- Attacks that still succeeded through every layer: {', '.join(s['residual_successes']) or 'none'}",
    ]
    errors = [c for c in report.cases if c.error]
    if errors:
        out += ["", "## Errors", ""] + [f"- `{c.id}`: {c.error}" for c in errors]
    return "\n".join(out) + "\n"
