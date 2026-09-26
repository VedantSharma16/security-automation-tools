"""Pluggable narrators that turn a TuningResult into analyst-readable prose.

Same design as `log-triage-assistant/logtriage/llm_summarizer.py`: the
*detection logic* (which variant was chosen, its precision/recall) is
produced entirely by deterministic code in `tuner.py` and is the source of
truth. A narrator only writes prose on top of that already-decided result --
it is explicitly barred from proposing different thresholds or field
values, so an LLM call here can never silently change what the rule
actually detects.

TemplateNarrator is dependency-free and always available; it's what the CLI
uses by default and what the test suite runs against. AnthropicNarrator is
opt-in (`--llm`) and requires the `anthropic` package plus an API key.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Protocol

from sigma_tuner.tuner import TuningResult

SYSTEM_PROMPT = (
    "You are a detection engineer writing the analyst notes for an automatically "
    "tuned Sigma-style detection rule. You are given ONLY a JSON object describing "
    "the technique, the rule variant that was selected, its precision/recall/F1 "
    "against labeled sample telemetry, and the tuning trace that led to it. Do not "
    "invent detection logic, field names, or values not present in the JSON, and do "
    "not suggest thresholds different from the one already selected. Write three "
    "short sections: 'Summary' (what was tuned and the result), 'Why this variant' "
    "(reference the trace: what earlier variants got wrong), and 'Deployment notes' "
    "(what to monitor, drawing on the listed false-positive sources). Be concise."
)


class Narrator(Protocol):
    def narrate(self, result: TuningResult, technique: dict) -> str: ...


class TemplateNarrator:
    """Deterministic, offline narrative built directly from the tuning trace."""

    def narrate(self, result: TuningResult, technique: dict) -> str:
        final = result.final_step
        m = final.metrics
        lines = [
            f"## Summary",
            "",
            f"Tuned a detection rule for {result.technique_id} ({technique['name']}) "
            f"across {len(result.steps)} candidate variant(s). "
            + (
                f"Variant '{final.variant_id}' met the target thresholds "
                f"(precision {m['precision']}, recall {m['recall']}, F1 {m['f1']})."
                if result.converged
                else (
                    f"No variant met both thresholds; '{final.variant_id}' was kept as the "
                    f"best available (precision {m['precision']}, recall {m['recall']}, F1 {m['f1']})."
                )
            ),
            "",
            "## Why this variant",
            "",
        ]
        for step in result.steps:
            marker = "-> selected" if step is final else "   rejected"
            lines.append(
                f"{marker} {step.variant_id}: {step.rationale} "
                f"[precision={step.metrics['precision']}, recall={step.metrics['recall']}, "
                f"f1={step.metrics['f1']}]"
            )
        lines += ["", "## Deployment notes", ""]
        if technique.get("falsepositives"):
            lines.append("Known false-positive sources to monitor after deployment:")
            for fp in technique["falsepositives"]:
                lines.append(f"- {fp}")
        else:
            lines.append("No known false-positive sources are recorded for this technique.")
        if not result.converged:
            lines.append(
                "\nThresholds were not met -- consider gathering more labeled telemetry "
                "or adding a KB variant with a different exclusion filter before deploying "
                "this rule in a blocking/alerting capacity."
            )
        return "\n".join(lines)


class AnthropicNarrator:
    """Sends the structured tuning result (never raw events) to a Claude model for prose."""

    def __init__(self, model: str = "claude-sonnet-5", api_key: str | None = None):
        from anthropic import Anthropic  # imported lazily so it's a true optional dependency

        self._client = Anthropic(api_key=api_key) if api_key else Anthropic()
        self._model = model

    def narrate(self, result: TuningResult, technique: dict) -> str:
        evidence = {
            "technique_id": result.technique_id,
            "technique_name": technique["name"],
            "converged": result.converged,
            "selected_variant": result.final_step.variant_id,
            "final_metrics": result.final_metrics,
            "trace": [
                {"variant_id": s.variant_id, "rationale": s.rationale, "metrics": s.metrics} for s in result.steps
            ],
            "falsepositives": technique.get("falsepositives", []),
        }
        response = self._client.messages.create(
            model=self._model,
            max_tokens=700,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": json.dumps(evidence, indent=2)}],
        )
        return "".join(block.text for block in response.content if block.type == "text")


def get_narrator(use_llm: bool, model: str = "claude-sonnet-5") -> Narrator:
    """Return an AnthropicNarrator if requested and usable, else the offline TemplateNarrator."""
    if not use_llm:
        return TemplateNarrator()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print(
            "note: --llm requested but ANTHROPIC_API_KEY is not set; "
            "falling back to the offline template narrator.",
            file=sys.stderr,
        )
        return TemplateNarrator()

    try:
        return AnthropicNarrator(model=model, api_key=api_key)
    except ImportError:
        print(
            "note: --llm requested but the 'anthropic' package is not installed; "
            "falling back to the offline template narrator.",
            file=sys.stderr,
        )
        return TemplateNarrator()
