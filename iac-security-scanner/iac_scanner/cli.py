"""Command-line interface for iac-security-scanner."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import report as report_mod
from . import scanner as scanner_mod
from .models import SEVERITIES, SEVERITY_RANK, IacScannerError
from .parser import parse_plan

# Exit codes let this tool gate a CI pipeline: fail the build if findings at
# or above --fail-on were found, without a human needing to read the output.
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

FAIL_ON_CHOICES = ("none",) + SEVERITIES


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iac-scanner",
        description="Scan Terraform plan JSON (from `terraform show -json`) for "
        "common AWS misconfigurations before they're applied.",
    )
    parser.add_argument("plan", type=Path, help="Path to a `terraform show -json` output file.")
    parser.add_argument(
        "--format", choices=("text", "markdown", "json"), default="text", help="Report format."
    )
    parser.add_argument(
        "--min-severity",
        choices=SEVERITIES,
        default="low",
        help="Only include findings at or above this severity in the report (default: low).",
    )
    parser.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        default="high",
        help="Exit 1 if any finding at or above this severity is present. "
        "Use 'none' to always exit 0 (default: high).",
    )
    parser.add_argument("--output", type=Path, help="Write the report to this path instead of stdout.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output.")
    return parser


def main(argv=None) -> int:
    arg_parser = build_parser()
    args = arg_parser.parse_args(argv)

    try:
        resources = parse_plan(args.plan)
    except (FileNotFoundError, IacScannerError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    findings = scanner_mod.scan(resources)
    full_report = report_mod.build_report(resources, findings)
    displayed = report_mod.filter_by_min_severity(full_report, args.min_severity)

    if args.format == "text":
        output = report_mod.render_text(displayed, use_color=not args.no_color)
    elif args.format == "markdown":
        output = report_mod.render_markdown(displayed)
    else:
        output = json.dumps(displayed, indent=2) + "\n"

    if args.output:
        args.output.write_text(output, encoding="utf-8")
    else:
        print(output, end="")

    if args.fail_on == "none":
        return EXIT_CLEAN

    threshold = SEVERITY_RANK[args.fail_on]
    if any(SEVERITY_RANK[f.severity] >= threshold for f in findings):
        return EXIT_FINDINGS
    return EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
