"""Command-line interface for Process Threat Hunter."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from . import baseline as baseline_mod
from . import report as report_mod
from .rules import SEVERITIES, load_rules
from .scanner import scan

DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "default_rules.yaml"

# Exit codes let this tool slot into cron jobs / CI pipelines that want to
# fail a build or page someone when something serious is running.
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="process-threat-hunter",
        description="Scan running processes against a rule set of known offensive "
        "security tooling and living-off-the-land binaries.",
    )
    parser.add_argument(
        "--rules", type=Path, default=DEFAULT_RULES_PATH, help="Path to a YAML rule file."
    )
    parser.add_argument(
        "--min-severity",
        choices=SEVERITIES,
        default="low",
        help="Only report findings at or above this severity (default: low).",
    )
    parser.add_argument("--json-out", type=Path, help="Write the full JSON report to this path.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output.")
    parser.add_argument(
        "--baseline",
        type=Path,
        help="Baseline file of known-good process fingerprints, used to flag new processes.",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Write the current process list to --baseline instead of diffing against it.",
    )
    parser.add_argument(
        "--watch",
        type=int,
        metavar="SECONDS",
        help="Run continuously, scanning every SECONDS seconds, instead of a single pass.",
    )
    return parser


def _run_once(args) -> dict:
    rules = load_rules(args.rules)
    processes, findings, scanned_at = scan(rules)

    new_processes = []
    if args.baseline and args.baseline.exists() and not args.update_baseline:
        known = baseline_mod.load_baseline(args.baseline)
        new_processes = baseline_mod.diff_baseline(processes, known)

    if args.baseline and args.update_baseline:
        baseline_mod.save_baseline(processes, args.baseline)

    report = report_mod.build_report(processes, findings, new_processes, scanned_at)
    report = report_mod.filter_by_min_severity(report, args.min_severity)

    print(report_mod.render_console(report, use_color=not args.no_color))

    if args.json_out:
        report_mod.write_json(report, args.json_out)

    return report


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.watch:
            while True:
                report = _run_once(args)
                print(f"\n--- next scan in {args.watch}s (Ctrl+C to stop) ---\n")
                time.sleep(args.watch)
        else:
            report = _run_once(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        return EXIT_CLEAN

    return EXIT_FINDINGS if report["finding_count"] else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
