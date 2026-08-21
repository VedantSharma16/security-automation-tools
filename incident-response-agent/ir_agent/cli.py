"""Command-line entrypoint for the incident-response agent.

Usage:
    ir-agent --file examples/sample_incident.txt
    cat incident.txt | ir-agent
    ir-agent --file incident.txt --json
    ir-agent --file incident.txt --offline   # force the deterministic planner
"""

from __future__ import annotations

import argparse
import json
import sys

from ir_agent.agent import DEFAULT_MAX_STEPS, run_agent, run_offline
from ir_agent.models import IncidentVerdict

_SEVERITY_ICONS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}


def _read_incident_text(args: argparse.Namespace) -> str:
    if args.file:
        with open(args.file, encoding="utf-8") as handle:
            return handle.read()
    if not sys.stdin.isatty():
        return sys.stdin.read()
    raise SystemExit("No input provided. Pass --file <path> or pipe incident text via stdin.")


def _render_human(verdict: IncidentVerdict) -> str:
    icon = _SEVERITY_ICONS.get(verdict.severity, "")
    lines = [
        f"{icon} Severity: {verdict.severity.upper()}  (confidence {verdict.confidence:.2f})",
        f"Planner: {'LLM (live tool-use)' if verdict.llm_backed else 'offline deterministic'}",
        "",
        f"Agent trace ({len(verdict.trace)} step(s)):",
    ]
    for step in verdict.trace:
        lines.append(f"  {step.step}. [{step.tool}] {step.thought}")
        if step.observation:
            lines.append(f"     -> {step.observation.summary}")

    lines += ["", "Recommended actions:"]
    for action in verdict.recommended_actions:
        lines.append(f"  - {action}")

    lines += ["", "Summary:", verdict.summary]
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ir-agent",
        description="Investigate a security incident with a tool-calling agent: check IPs, "
        "domains, and CVEs against local intel, match ATT&CK techniques, and produce a "
        "structured triage verdict with a full reasoning trace.",
    )
    parser.add_argument("--file", "-f", help="Path to a file containing the raw incident/alert text.")
    parser.add_argument("--json", action="store_true", help="Output the full verdict (with trace) as JSON.")
    parser.add_argument("--max-steps", type=int, default=DEFAULT_MAX_STEPS, help="Maximum agent loop iterations.")
    parser.add_argument(
        "--offline", action="store_true", help="Force the deterministic offline planner, even if an API key is set."
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    incident_text = _read_incident_text(args)

    if args.offline:
        verdict = run_offline(incident_text, max_steps=args.max_steps)
    else:
        verdict = run_agent(incident_text, max_steps=args.max_steps)

    if args.json:
        print(json.dumps(verdict.to_dict(), indent=2))
    else:
        print(_render_human(verdict))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
