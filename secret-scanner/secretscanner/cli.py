"""Command-line interface for Secret Scanner."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import baseline as baseline_mod
from . import report as report_mod
from .rules import SEVERITIES, load_default_rules, load_rules
from .scanner import scan_path

# Exit codes let this tool slot into a CI pipeline as a merge/push gate.
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret-scanner",
        description="Scan a directory tree for hardcoded credentials: vendor API keys, "
        "private keys, connection strings, and generic high-entropy secrets.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Directory to scan (default: .)")
    parser.add_argument("--rules", type=Path, help="Path to a custom YAML rule file.")
    parser.add_argument(
        "--min-severity",
        choices=SEVERITIES,
        default="low",
        help="Only report findings at or above this severity (default: low).",
    )
    parser.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        default="low",
        help="Exit 1 only if a finding at or above this severity is present "
        "(default: low, i.e. any reported finding fails the scan).",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="Glob (relative to the scan path) to exclude; repeatable.",
    )
    parser.add_argument("--json-out", type=Path, help="Write the full JSON report to this path.")
    parser.add_argument("--sarif-out", type=Path, help="Write a SARIF report to this path (for GitHub code scanning).")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output.")
    parser.add_argument(
        "--baseline",
        type=Path,
        help="Baseline file of previously-accepted finding fingerprints; "
        "matching findings are suppressed from output and the exit code.",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Write the current findings to --baseline instead of diffing against it.",
    )
    return parser


def _run(args) -> dict:
    rules = load_rules(args.rules) if args.rules else load_default_rules()
    root = Path(args.path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"scan path does not exist: {root}")

    findings, files_scanned = scan_path(root, rules, exclude_globs=tuple(args.exclude))

    if args.baseline and args.update_baseline:
        baseline_mod.save_baseline(findings, args.baseline)

    suppressed = 0
    if args.baseline and args.baseline.exists() and not args.update_baseline:
        known = baseline_mod.load_baseline(args.baseline)
        before = len(findings)
        findings = baseline_mod.filter_new(findings, known)
        suppressed = before - len(findings)

    report = report_mod.build_report(findings, str(root), files_scanned, suppressed_by_baseline=suppressed)
    fail_relevant = report_mod.filter_by_min_severity(report, args.fail_on)["findings"]
    report = report_mod.filter_by_min_severity(report, args.min_severity)

    print(report_mod.render_console(report, use_color=not args.no_color))

    if args.json_out:
        report_mod.write_json(report, args.json_out)
    if args.sarif_out:
        report_mod.write_sarif(report, args.sarif_out)

    report["_should_fail"] = bool(fail_relevant)
    return report


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        report = _run(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    return EXIT_FINDINGS if report["_should_fail"] else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
