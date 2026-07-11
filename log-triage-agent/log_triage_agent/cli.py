"""Command-line entry point.

    python -m log_triage_agent --log data/sample_auth.log
    python -m log_triage_agent --log data/sample_auth.log --out report.md --year 2026
"""

import argparse
import sys

from .detectors import run_all_detectors
from .parsers import parse_file
from .reporter import generate_report


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-triage-agent",
        description="Parse an SSH auth log, detect suspicious activity, and "
        "generate a MITRE ATT&CK-mapped incident report.",
    )
    parser.add_argument("--log", required=True, help="Path to an auth.log-style file.")
    parser.add_argument("--out", help="Write the Markdown report here instead of stdout.")
    parser.add_argument(
        "--year",
        type=int,
        default=None,
        help="Year to assume for timestamps (syslog lines omit it). Defaults to the current year.",
    )
    return parser


def main(argv=None) -> int:
    args = build_arg_parser().parse_args(argv)

    try:
        events = parse_file(args.log, year=args.year)
    except FileNotFoundError:
        print(f"error: log file not found: {args.log}", file=sys.stderr)
        return 1

    findings = run_all_detectors(events)
    report = generate_report(findings)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"Report written to {args.out} ({len(findings)} finding(s)).")
    else:
        print(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
