"""secretscan command-line interface.

  secretscan scan <path> [--include-git] [--baseline FILE] [--format json|table]
  secretscan baseline <path> [--include-git] --out FILE
"""

from __future__ import annotations

import argparse
import os
import sys

from .baseline import load_baseline, save_baseline
from .models import ScanResult
from .report import to_json, to_table
from .scanner import scan_git_history, scan_working_tree

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _collect_findings(args: argparse.Namespace) -> list:
    if not os.path.isdir(args.path):
        raise NotADirectoryError(f"no such directory: {args.path}")
    findings = scan_working_tree(
        args.path, min_entropy=args.min_entropy, extra_excludes=set(args.exclude or [])
    )
    if args.include_git:
        findings.extend(
            scan_git_history(
                args.path, min_entropy=args.min_entropy, max_commits=args.max_commits
            )
        )
    return findings


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        findings = _collect_findings(args)
    except Exception as exc:  # surfaced as a clean CLI error, not a traceback
        print(f"secretscan: scan failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    baselined = load_baseline(args.baseline) if args.baseline else set()
    result = ScanResult(findings=findings, baselined_fingerprints=baselined)

    output = to_json(result) if args.format == "json" else to_table(
        result, show_baselined=args.show_baselined
    )

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(output + "\n")
    else:
        print(output)

    return EXIT_FINDINGS if result.new_findings else EXIT_CLEAN


def cmd_baseline(args: argparse.Namespace) -> int:
    try:
        findings = _collect_findings(args)
    except Exception as exc:
        print(f"secretscan: baseline generation failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    save_baseline(findings, args.out)
    print(f"Wrote baseline with {len(findings)} accepted finding(s) to {args.out}")
    return EXIT_CLEAN


def _add_scan_source_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("path", help="Directory to scan")
    parser.add_argument(
        "--include-git",
        action="store_true",
        help="Also scan full git history (catches secrets since removed from the working tree)",
    )
    parser.add_argument(
        "--max-commits", type=int, default=None, help="Limit git history scan to N most recent commits"
    )
    parser.add_argument(
        "--min-entropy",
        type=float,
        default=3.5,
        help="Shannon entropy floor for the generic secret heuristic (default: 3.5)",
    )
    parser.add_argument(
        "--exclude", action="append", default=[], help="Additional directory name to skip (repeatable)"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secretscan", description="Offline secret/credential leak scanner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a directory (and optionally its git history)")
    _add_scan_source_args(scan_parser)
    scan_parser.add_argument("--format", choices=["table", "json"], default="table")
    scan_parser.add_argument("--out", help="Write report to a file instead of stdout")
    scan_parser.add_argument("--baseline", help="Baseline file of accepted findings to suppress")
    scan_parser.add_argument(
        "--show-baselined", action="store_true", help="Include baselined findings in table output"
    )
    scan_parser.set_defaults(func=cmd_scan)

    baseline_parser = subparsers.add_parser(
        "baseline", help="Record current findings as accepted, suppressing them from future scans"
    )
    _add_scan_source_args(baseline_parser)
    baseline_parser.add_argument("--out", required=True, help="Baseline file to write")
    baseline_parser.set_defaults(func=cmd_baseline)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
