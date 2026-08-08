"""Command-line entry point: investigate an alert JSON file and emit a report."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from investigator.engine import investigate
from investigator.report import to_json, to_markdown
from investigator.state import Alert


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="investigator",
        description="Run the agentic tool-calling loop over a security alert and produce a triage report.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("investigate", help="Investigate an alert JSON file.")
    scan.add_argument("alertfile", help="Path to a JSON file describing the alert.")
    scan.add_argument("--format", choices=["json", "markdown"], default="markdown", help="Output format.")
    scan.add_argument("--out", help="Write the report to this file instead of stdout.")
    scan.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip the live LLM agent and always use the deterministic offline planner.",
    )

    return parser


def run_investigate(args: argparse.Namespace) -> int:
    alertfile = Path(args.alertfile)
    if not alertfile.is_file():
        print(f"error: no such file: {alertfile}", file=sys.stderr)
        return 1

    alert = Alert.from_dict(json.loads(alertfile.read_text(encoding="utf-8")))
    result = investigate(alert, use_llm=not args.no_llm)
    output = to_json(result) if args.format == "json" else to_markdown(result)

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
