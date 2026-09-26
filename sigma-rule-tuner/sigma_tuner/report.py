"""Combine a TuningResult + narrative into a serializable report."""

from __future__ import annotations

from sigma_tuner.tuner import TuningResult
from sigma_tuner.yaml_dump import dump as yaml_dump


def build_report(result: TuningResult, technique_id: str, technique: dict, narrative: str) -> dict:
    return {
        "technique_id": technique_id,
        "technique_name": technique["name"],
        "converged": result.converged,
        "iterations_tried": len(result.steps),
        "selected_variant": result.final_step.variant_id,
        "final_metrics": result.final_metrics,
        "final_rule": result.final_rule,
        "trace": [
            {"variant_id": s.variant_id, "rationale": s.rationale, "metrics": s.metrics} for s in result.steps
        ],
        "narrative": narrative,
    }


def render_markdown(report: dict) -> str:
    lines = [
        f"# Sigma rule tuning report: {report['technique_id']} ({report['technique_name']})",
        "",
        f"**Converged:** {report['converged']}  ",
        f"**Selected variant:** `{report['selected_variant']}`  ",
        f"**Iterations tried:** {report['iterations_tried']}",
        "",
        "## Tuning trace",
        "",
        "| Variant | Precision | Recall | F1 | Rationale |",
        "|---|---|---|---|---|",
    ]
    for step in report["trace"]:
        m = step["metrics"]
        lines.append(f"| `{step['variant_id']}` | {m['precision']} | {m['recall']} | {m['f1']} | {step['rationale']} |")

    lines += ["", "## Final Sigma rule", "", "```yaml", yaml_dump(report["final_rule"]).rstrip("\n"), "```", ""]
    lines += [report["narrative"]]
    return "\n".join(lines)
