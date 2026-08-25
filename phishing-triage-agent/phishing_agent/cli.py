"""Command-line entrypoint for the phishing triage agent.

Usage:
    phishing-agent --file examples/phishing_sample.eml
    phishing-agent --file examples/benign_sample.eml --json
    cat suspicious.eml | phishing-agent
"""

from __future__ import annotations

import argparse
import json
import sys

from phishing_agent.agent import DEFAULT_MAX_STEPS, DEFAULT_MODEL, PhishingAgent
from phishing_agent.email_parser import parse_eml
from phishing_agent.report import render_human


def _read_raw(args: argparse.Namespace) -> bytes:
    if args.file:
        with open(args.file, "rb") as handle:
            return handle.read()
    if not sys.stdin.isatty():
        return sys.stdin.buffer.read()
    raise SystemExit("No input provided. Pass --file <path.eml> or pipe an .eml via stdin.")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishing-agent",
        description="Investigate a raw .eml message with a tool-calling triage agent "
        "and produce a phishing/suspicious/benign verdict with evidence.",
    )
    parser.add_argument("--file", "-f", help="Path to a raw .eml file.")
    parser.add_argument("--json", action="store_true", help="Output the full result as JSON.")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Anthropic model to use in live mode.")
    parser.add_argument(
        "--max-steps", type=int, default=DEFAULT_MAX_STEPS,
        help="Max tool-call rounds before forcing a verdict in live mode.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    raw = _read_raw(args)

    email = parse_eml(raw)
    agent = PhishingAgent(model=args.model, max_steps=args.max_steps)
    result = agent.investigate(email)

    if args.json:
        print(json.dumps({"email": email.to_dict(), "result": result.to_dict()}, indent=2))
    else:
        print(render_human(email, result))

    return 1 if result.verdict != "benign" else 0


if __name__ == "__main__":
    raise SystemExit(main())
