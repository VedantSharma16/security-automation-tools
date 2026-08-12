"""Command-line entry point for soc-agent."""

from __future__ import annotations

import argparse
import json
import sys

from .agent import DEFAULT_MODEL, SocAgent
from .models import Alert, AgentResult

_VERDICT_ICON = {
    "malicious": "\U0001f534",
    "suspicious": "\U0001f7e0",
    "benign": "\U0001f7e2",
    "inconclusive": "⚪",
}


def _load_alert(args: argparse.Namespace) -> Alert:
    if args.file:
        with open(args.file, encoding="utf-8") as handle:
            raw = handle.read()
    else:
        raw = sys.stdin.read()
    data = json.loads(raw)
    return Alert.from_dict(data)


def _render_human(result: AgentResult) -> str:
    icon = _VERDICT_ICON.get(result.verdict.verdict, "⚪")
    lines = [
        f"{icon} Verdict: {result.verdict.verdict.upper()} (confidence={result.verdict.confidence})",
        f"Mode: {result.mode}",
        "",
        f"Rationale: {result.verdict.rationale}",
        f"Recommended action: {result.verdict.recommended_action}",
        "",
        f"Investigation trace ({len(result.trace)} step(s)):",
    ]
    for step in result.trace:
        input_repr = ", ".join(f"{k}={v!r}" for k, v in step.input.items())
        lines.append(f"  {step.step}. {step.tool}({input_repr})")
        if step.output is not None:
            summary = json.dumps(step.output)
            if len(summary) > 160:
                summary = summary[:157] + "..."
            lines.append(f"       -> {summary}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="soc-agent", description="Agentic SOC alert triage assistant.")
    parser.add_argument("--file", help="Path to a JSON alert file. Defaults to reading JSON from stdin.")
    parser.add_argument("--json", action="store_true", help="Print the full result as JSON instead of a human report.")
    parser.add_argument("--max-steps", type=int, default=8, help="Maximum tool-call steps before giving up (default: 8).")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Anthropic model to use in live mode (default: {DEFAULT_MODEL}).")
    args = parser.parse_args(argv)

    alert = _load_alert(args)
    agent = SocAgent(model=args.model)
    result = agent.investigate(alert, max_steps=args.max_steps)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        if not agent.is_live:
            print("LLM-backed: no (offline deterministic planner — set ANTHROPIC_API_KEY for a live tool-calling agent)\n")
        print(_render_human(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
