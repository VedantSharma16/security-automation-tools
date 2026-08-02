"""Command-line interface for Secrets Scanner."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from . import baseline as baseline_mod
from . import report as report_mod
from .entropy import DEFAULT_MIN_ENTROPY, DEFAULT_MIN_LENGTH
from .git_scanner import GitScanError, scan_git_history
from .rules import SEVERITIES, RuleValidationError, load_rules
from .scanner import scan_paths
from .triage import triage_findings

DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "default_rules.yaml"

# Exit codes let this tool gate a pre-commit hook or CI step.
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secretscan",
        description="Scan a working tree (and optionally its git history) for hardcoded "
        "secrets using vendor-specific signatures and generic entropy detection.",
    )
    parser.add_argument(
        "paths", nargs="*", default=["."], help="Files or directories to scan (default: .)."
    )
    parser.add_argument(
        "--rules", type=Path, default=DEFAULT_RULES_PATH, help="Path to a YAML rule file."
    )
    parser.add_argument(
        "--no-entropy", action="store_true", help="Disable generic high-entropy secret detection."
    )
    parser.add_argument(
        "--min-entropy",
        type=float,
        default=DEFAULT_MIN_ENTROPY,
        help=f"Minimum Shannon entropy (bits/char) for the entropy detector (default: {DEFAULT_MIN_ENTROPY}).",
    )
    parser.add_argument(
        "--min-length",
        type=int,
        default=DEFAULT_MIN_LENGTH,
        help=f"Minimum value length for the entropy detector (default: {DEFAULT_MIN_LENGTH}).",
    )
    parser.add_argument(
        "--min-severity",
        choices=SEVERITIES,
        default="low",
        help="Only report findings at or above this severity (default: low).",
    )
    parser.add_argument(
        "--git-history",
        action="store_true",
        help="Also scan every line ever added in the repo's commit history (first path must be a git repo).",
    )
    parser.add_argument(
        "--all-branches", action="store_true", help="With --git-history, scan all branches, not just HEAD."
    )
    parser.add_argument(
        "--max-commits", type=int, help="With --git-history, limit the scan to the N most recent commits."
    )
    parser.add_argument(
        "--baseline", type=Path, help="Baseline file of previously reviewed findings to suppress."
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Write current findings to --baseline instead of suppressing against it.",
    )
    parser.add_argument(
        "--triage",
        action="store_true",
        help="Annotate findings with a likely-secret / false-positive verdict "
        "(uses ANTHROPIC_API_KEY if set, otherwise an offline heuristic).",
    )
    parser.add_argument("--json-out", type=Path, help="Write the full JSON report to this path.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output.")
    return parser


def _run(args) -> dict:
    rules = load_rules(args.rules)
    enable_entropy = not args.no_entropy

    findings = scan_paths(
        args.paths,
        rules,
        enable_entropy=enable_entropy,
        min_entropy=args.min_entropy,
        min_length=args.min_length,
    )

    if args.git_history:
        repo_root = Path(args.paths[0])
        try:
            findings += scan_git_history(
                repo_root,
                rules,
                enable_entropy=enable_entropy,
                max_commits=args.max_commits,
                all_branches=args.all_branches,
                min_entropy=args.min_entropy,
                min_length=args.min_length,
            )
        except GitScanError as exc:
            print(f"warning: git history scan skipped: {exc}", file=sys.stderr)

    if args.baseline and args.baseline.exists() and not args.update_baseline:
        known = baseline_mod.load_baseline(args.baseline)
        findings = baseline_mod.apply_baseline(findings, known)

    if args.baseline and args.update_baseline:
        baseline_mod.save_baseline(findings, args.baseline)

    triage_map = triage_findings(findings, use_llm=True) if args.triage else {}

    report = report_mod.build_report(findings, triage=triage_map, scanned_at=time.time())
    report = report_mod.filter_by_min_severity(report, args.min_severity)

    print(report_mod.render_console(report, use_color=not args.no_color))

    if args.json_out:
        report_mod.write_json(report, args.json_out)

    return report


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        report = _run(args)
    except (FileNotFoundError, RuleValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    return EXIT_FINDINGS if report["finding_count"] else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
