"""Command-line entrypoint for the recon agent.

Usage:
    recon-agent --target example.com
    recon-agent --target example.com --json
    recon-agent --target example.com --max-steps 8
"""

from __future__ import annotations

import argparse
import json

from recon_agent.agent import DEFAULT_MAX_STEPS, DEFAULT_MODEL, ReconAgent
from recon_agent.report import render_human


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recon-agent",
        description=(
            "Agentic, passive attack-surface recon assistant. Only ever point this at a "
            "target you are explicitly authorized to test."
        ),
    )
    parser.add_argument("--target", "-t", required=True, help="Domain to investigate, e.g. example.com")
    parser.add_argument("--json", action="store_true", help="Output the full report as JSON.")
    parser.add_argument("--max-steps", type=int, default=DEFAULT_MAX_STEPS, help="Max agentic tool-call rounds.")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Claude model to use for the agentic run.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    agent = ReconAgent(model=args.model, max_steps=args.max_steps)
    report = agent.run(args.target)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(render_human(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
