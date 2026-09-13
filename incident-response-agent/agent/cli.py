"""Command-line entry point: investigate an alert and print a report."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import DEFAULT_MAX_TURNS, investigate
from .environment import Environment
from .planners import DEFAULT_MODEL, get_planner
from .report import to_json, to_markdown


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ir-agent",
        description="Autonomously investigate a security alert against a simulated SOC environment.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    investigate_cmd = subparsers.add_parser(
        "investigate", help="Investigate a single alert file and produce a report."
    )
    investigate_cmd.add_argument("alert_file", help="Path to a JSON alert file.")
    investigate_cmd.add_argument(
        "--data-dir", help="Directory containing hosts.json/processes.json/auth.log/ioc_feed.json."
    )
    investigate_cmd.add_argument(
        "--format", choices=["markdown", "json"], default="markdown", help="Output format."
    )
    investigate_cmd.add_argument("--out", help="Write the report to this file instead of stdout.")
    investigate_cmd.add_argument(
        "--max-turns", type=int, default=DEFAULT_MAX_TURNS, help="Max tool-call turns before giving up."
    )
    investigate_cmd.add_argument(
        "--llm",
        action="store_true",
        help="Use Claude to drive the investigation (requires ANTHROPIC_API_KEY); "
        "falls back to the offline planner if no key is set.",
    )
    investigate_cmd.add_argument("--model", default=DEFAULT_MODEL, help="Model to use when --llm is set.")

    return parser


def run_investigate(args: argparse.Namespace) -> int:
    alert_path = Path(args.alert_file)
    if not alert_path.is_file():
        print(f"error: no such file: {alert_path}", file=sys.stderr)
        return 1

    alert = json.loads(alert_path.read_text(encoding="utf-8"))
    env_kwargs = {"data_dir": args.data_dir} if args.data_dir else {}
    environment = Environment.load(**env_kwargs)
    planner = get_planner(args.llm, model=args.model)

    report = investigate(alert, environment, planner, max_turns=args.max_turns)
    output = to_json(report) if args.format == "json" else to_markdown(report)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
    else:
        print(output)

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "investigate":
        return run_investigate(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
