"""Command-line interface for secretscan."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import allowlist as allowlist_mod
from . import git_history
from . import llm_summary
from . import report as report_mod
from .rules import SEVERITIES, DEFAULT_RULES
from .scanner import scan_directory

# CI-friendly exit codes.
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secretscan",
        description="Scan a directory (and optionally its git history) for hardcoded secrets.",
    )
    parser.add_argument("path", type=Path, nargs="?", default=Path("."), help="Directory to scan (default: .).")
    parser.add_argument(
        "--git-history",
        action="store_true",
        help="Also scan every added line across the repo's commit history, not just the working tree.",
    )
    parser.add_argument(
        "--current-branch-only",
        action="store_true",
        help="With --git-history, scan only the current branch instead of all branches.",
    )
    parser.add_argument("--max-commits", type=int, help="With --git-history, scan only the N most recent commits.")
    parser.add_argument(
        "--no-entropy",
        action="store_true",
        help="Disable the high-entropy generic-secret heuristic; report only known secret formats.",
    )
    parser.add_argument(
        "--min-severity", choices=SEVERITIES, default="low", help="Only report findings at or above this severity."
    )
    parser.add_argument(
        "--allowlist", type=Path, default=Path(".secretsallowlist"), help="Path to a .secretsallowlist file."
    )
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Console output format.")
    parser.add_argument("--json-out", type=Path, help="Also write the full JSON report to this path.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output.")
    parser.add_argument(
        "--llm", action="store_true", help="Generate the executive summary with Claude instead of the offline template."
    )
    parser.add_argument("--llm-model", default="claude-sonnet-5", help="Model to use with --llm.")
    parser.add_argument("--no-summary", action="store_true", help="Skip the executive summary section entirely.")
    return parser


def run(args) -> dict:
    if not args.path.is_dir():
        raise FileNotFoundError(f"not a directory: {args.path}")

    allowlist = allowlist_mod.load(args.allowlist)
    use_entropy = not args.no_entropy

    findings = scan_directory(args.path, rules=DEFAULT_RULES, use_entropy=use_entropy, allowlist=allowlist)

    targets = {"working_tree": str(args.path), "git_history": False}
    if args.git_history:
        targets["git_history"] = True
        targets["all_branches"] = not args.current_branch_only
        findings += git_history.scan_git_history(
            args.path,
            rules=DEFAULT_RULES,
            use_entropy=use_entropy,
            allowlist=allowlist,
            all_branches=not args.current_branch_only,
            max_commits=args.max_commits,
        )

    report = report_mod.build_report(findings, scan_targets=targets)
    report = report_mod.filter_by_min_severity(report, args.min_severity)

    if not args.no_summary:
        summarizer = llm_summary.get_summarizer(args.llm, model=args.llm_model)
        report["executive_summary"] = summarizer.summarize(report)

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(report_mod.render_console(report, use_color=not args.no_color))
        if not args.no_summary:
            print("\n--- Executive Summary ---\n")
            print(report["executive_summary"])

    if args.json_out:
        report_mod.write_json(report, args.json_out)

    return report


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        report = run(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except git_history.GitError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        return EXIT_CLEAN

    return EXIT_FINDINGS if report["finding_count"] else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
