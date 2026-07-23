"""Command-line entry point: parse a .eml file, run heuristics, and emit a report."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .heuristics import run_all_heuristics
from .llm_summarizer import get_summarizer
from .parser import parse_file
from .report import build_report, to_json, to_markdown


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishtriage",
        description="Parse a .eml file and triage it for phishing indicators.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan an .eml file and produce a triage report.")
    scan.add_argument("emlfile", help="Path to the .eml file to analyze.")
    scan.add_argument(
        "--format", choices=["json", "markdown"], default="markdown", help="Output format."
    )
    scan.add_argument("--out", help="Write the report to this file instead of stdout.")
    scan.add_argument(
        "--llm",
        action="store_true",
        help="Use Claude to write the narrative section (requires ANTHROPIC_API_KEY).",
    )
    scan.add_argument(
        "--model", default="claude-sonnet-5", help="Model to use when --llm is set."
    )

    return parser


def run_scan(args: argparse.Namespace) -> int:
    emlfile = Path(args.emlfile)
    if not emlfile.is_file():
        print(f"error: no such file: {emlfile}", file=sys.stderr)
        return 1

    email = parse_file(emlfile)
    findings = run_all_heuristics(email)
    report = build_report(emlfile, email, findings)

    summarizer = get_summarizer(args.llm, model=args.model)
    report["narrative"] = summarizer.summarize(report)

    output = to_json(report) if args.format == "json" else to_markdown(report)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
    else:
        print(output)

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
