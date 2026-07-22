"""Command-line entrypoint for the incident-response agent.

Usage:
    ir-agent --file examples/sample_incident.txt
    cat incident.txt | ir-agent
    ir-agent --file incident.txt --json
"""

from __future__ import annotations

import argparse
import sys

from ir_agent.agent import IncidentResponseAgent
from ir_agent.report import to_json, to_markdown


def _read_incident_text(args: argparse.Namespace) -> str:
    if args.file:
        with open(args.file, encoding="utf-8") as handle:
            return handle.read()
    if not sys.stdin.isatty():
        return sys.stdin.read()
    raise SystemExit("No input provided. Pass --file <path> or pipe incident text via stdin.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Investigate an incident with the ir-agent.")
    parser.add_argument("--file", help="Path to a file containing the raw incident/alert text.")
    parser.add_argument("--json", action="store_true", help="Output the report as JSON.")
    parser.add_argument(
        "--no-transcript",
        action="store_true",
        help="Omit the tool-call transcript from markdown output.",
    )
    parser.add_argument("--model", default=None, help="Override the Claude model to use in live mode.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    incident_text = _read_incident_text(args)

    agent_kwargs = {}
    if args.model:
        agent_kwargs["model"] = args.model
    agent = IncidentResponseAgent(**agent_kwargs)

    result = agent.investigate(incident_text)

    if args.json:
        print(to_json(result))
    else:
        print(to_markdown(result, include_transcript=not args.no_transcript))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
