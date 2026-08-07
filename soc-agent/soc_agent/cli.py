"""Command-line entrypoint for the SOC agent.

Usage:
    soc-agent --file examples/sample_alert.txt
    cat alert.txt | soc-agent
    soc-agent --file alert.txt --json
    soc-agent --file alert.txt --no-trace
"""

from __future__ import annotations

import argparse
import sys

from soc_agent.agent import investigate
from soc_agent.report import render_json, render_text


def _read_alert_text(args: argparse.Namespace) -> str:
    if args.file:
        with open(args.file, encoding="utf-8") as handle:
            return handle.read()
    if not sys.stdin.isatty():
        return sys.stdin.read()
    raise SystemExit("No input provided. Pass --file <path> or pipe alert text via stdin.")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-agent",
        description="Agentic SOC investigator: runs a tool-calling investigation loop over a "
        "raw security alert and produces a verdict with a full evidence trace.",
    )
    parser.add_argument("--file", "-f", help="Path to a file containing the raw alert text.")
    parser.add_argument("--json", action="store_true", help="Output the full result as JSON.")
    parser.add_argument("--no-trace", action="store_true", help="Hide the step-by-step trace in text output.")
    parser.add_argument("--max-steps", type=int, default=6, help="Max tool-calling steps for the live agent.")
    parser.add_argument("--api-key", help="Anthropic API key (defaults to ANTHROPIC_API_KEY env var).")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    alert_text = _read_alert_text(args)

    result = investigate(alert_text, api_key=args.api_key, max_steps=args.max_steps)

    if args.json:
        print(render_json(result))
    else:
        print(render_text(result, show_trace=not args.no_trace))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
