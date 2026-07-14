"""Command-line interface for log-sentinel."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from .detector import DetectorConfig, detect
from .parser import parse_file
from .report import findings_to_dicts, get_report_generator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-sentinel",
        description="Detect SSH auth-log anomalies and generate an incident report.",
    )
    parser.add_argument("log_file", help="Path to an OpenSSH auth log (syslog format).")
    parser.add_argument(
        "--brute-force-threshold",
        type=int,
        default=5,
        help="Failed attempts from one IP within the window to flag brute force (default: 5).",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=60,
        dest="window_seconds",
        help="Sliding window in seconds for brute-force detection (default: 60).",
    )
    parser.add_argument(
        "--enum-threshold",
        type=int,
        default=3,
        help="Distinct invalid usernames from one IP to flag enumeration (default: 3).",
    )
    parser.add_argument(
        "--off-hours-start",
        type=int,
        default=6,
        help="Start of business hours, 24h clock (default: 6).",
    )
    parser.add_argument(
        "--off-hours-end",
        type=int,
        default=22,
        help="End of business hours, 24h clock (default: 22).",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Report output format (default: markdown).",
    )
    parser.add_argument(
        "--use-llm",
        action="store_true",
        help="Generate the report with the Anthropic API instead of the offline template "
        "(requires the 'anthropic' package and ANTHROPIC_API_KEY; falls back automatically).",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Write the report to a file instead of stdout.",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "never"],
        default="never",
        help="Exit with status 2 if a finding at or above this severity is present "
        "(useful in CI/cron pipelines). Default: never.",
    )
    return parser


_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    log_path = Path(args.log_file)
    if not log_path.exists():
        print(f"log-sentinel: no such file: {log_path}", file=sys.stderr)
        return 1

    entries = parse_file(log_path)
    config = DetectorConfig(
        brute_force_threshold=args.brute_force_threshold,
        brute_force_window_seconds=args.window_seconds,
        enumeration_threshold=args.enum_threshold,
        off_hours_start=args.off_hours_start,
        off_hours_end=args.off_hours_end,
    )
    findings = detect(entries, config=config)

    if args.format == "json":
        report = json.dumps(findings_to_dicts(findings), indent=2)
    else:
        generator = get_report_generator(use_llm=args.use_llm)
        report = generator.generate(findings, source_label=str(log_path))

    if args.output:
        args.output.write_text(report, encoding="utf-8")
    else:
        print(report)

    if args.fail_on != "never":
        threshold_rank = _SEVERITY_RANK[args.fail_on]
        if any(_SEVERITY_RANK[f.severity.value] >= threshold_rank for f in findings):
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
