"""Command-line entry point: parse a log file, run detectors, and emit a report."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .detectors import (
    DEFAULT_BRUTE_FORCE_THRESHOLD,
    DEFAULT_BRUTE_FORCE_WINDOW_SECONDS,
    run_all_detectors,
)
from .llm_summarizer import get_summarizer
from .parser import parse_file
from .report import build_report, to_json, to_markdown


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logtriage",
        description="Parse an auth-log style file and triage it for intrusion indicators.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan a log file and produce a triage report.")
    scan.add_argument("logfile", help="Path to the log file to analyze.")
    scan.add_argument(
        "--format", choices=["json", "markdown"], default="markdown", help="Output format."
    )
    scan.add_argument("--out", help="Write the report to this file instead of stdout.")
    scan.add_argument(
        "--window",
        type=int,
        default=DEFAULT_BRUTE_FORCE_WINDOW_SECONDS,
        help="Brute-force detection window, in seconds.",
    )
    scan.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_BRUTE_FORCE_THRESHOLD,
        help="Minimum failed attempts within the window to flag brute force.",
    )
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
    logfile = Path(args.logfile)
    if not logfile.is_file():
        print(f"error: no such file: {logfile}", file=sys.stderr)
        return 1

    events = parse_file(logfile)
    findings = run_all_detectors(events, window_seconds=args.window, threshold=args.threshold)
    report = build_report(logfile, events, findings)

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
