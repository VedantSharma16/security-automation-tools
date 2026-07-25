"""Command-line entrypoint for the agentic SOC copilot.

Usage:
    soc-agent --file examples/sample_alert.txt
    cat alert.txt | soc-agent
    soc-agent --file alert.txt --json
"""

from __future__ import annotations

import argparse
import json
import sys

from agentic_soc.agent import SocAgent
from agentic_soc.transcript import AgentTranscript

_VERDICT_ICONS = {"malicious": "🔴", "suspicious": "🟡", "benign": "🟢"}


def _read_alert_text(args: argparse.Namespace) -> str:
    if args.file:
        with open(args.file, encoding="utf-8") as handle:
            return handle.read()
    if not sys.stdin.isatty():
        return sys.stdin.read()
    raise SystemExit("No input provided. Pass --file <path> or pipe alert text via stdin.")


def _render_human(transcript: AgentTranscript) -> str:
    lines = [
        f"Agent backend: {'live LLM tool-use' if transcript.llm_backed else 'offline deterministic planner'}",
        f"Steps taken: {transcript.steps_used}",
        "",
        "Investigation trace:",
    ]
    for i, step in enumerate(transcript.steps, start=1):
        lines.append(f"  {i}. {step.thought}")
        lines.append(f"     -> {step.tool}({step.tool_input})")
        lines.append(f"     <- {json.dumps(step.observation)}")

    icon = _VERDICT_ICONS.get(transcript.verdict.verdict, "")
    lines += [
        "",
        f"{icon} Verdict: {transcript.verdict.verdict.upper()} (confidence={transcript.verdict.confidence:.2f})",
        "",
        "Reasoning:",
        f"  {transcript.verdict.reasoning}",
        "",
        "Recommended actions:",
    ]
    for action in transcript.verdict.recommended_actions:
        lines.append(f"  - {action}")
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-agent",
        description="Investigate a security alert with an autonomous tool-calling SOC triage agent.",
    )
    parser.add_argument("--file", "-f", help="Path to a file containing the raw alert text.")
    parser.add_argument("--json", action="store_true", help="Output the full investigation transcript as JSON.")
    parser.add_argument("--max-steps", type=int, default=6, help="Max tool-calling steps before failing safe.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    alert_text = _read_alert_text(args)

    agent = SocAgent(max_steps=args.max_steps)
    transcript = agent.investigate(alert_text)

    if args.json:
        print(json.dumps(transcript.to_dict(), indent=2))
    else:
        print(_render_human(transcript))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
