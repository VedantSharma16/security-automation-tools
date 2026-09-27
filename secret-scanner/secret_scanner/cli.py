"""Command-line entrypoint for secret-scanner.

Usage:
    secret-scanner scan .
    secret-scanner scan . --git-history
    secret-scanner scan . --git-history --since v1.0.0 --min-severity high
    secret-scanner scan . --json-out report.json --markdown-out report.md
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .allowlist import Allowlist, load_allowlist_file
from .entropy import EntropyConfig
from .git_history import scan_git_history
from .llm_triage import get_summarizer
from .report import build_report, filter_by_min_severity, render_console, write_json, write_markdown
from .scanner import scan_working_tree

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret-scanner",
        description="Scan a working tree (and optionally full git history) for hardcoded secrets.",
    )
    parser.add_argument("path", nargs="?", default=".", type=Path, help="Directory to scan (default: .)")
    parser.add_argument(
        "--git-history", action="store_true", help="Also scan every commit's added lines for secrets."
    )
    parser.add_argument("--since", metavar="REF", help="Only scan git history back to this ref (exclusive).")
    parser.add_argument("--max-commits", type=int, help="Limit how many commits of history to scan.")
    parser.add_argument(
        "--min-severity", choices=("low", "medium", "high", "critical"), default="low",
        help="Only report findings at or above this severity (default: low).",
    )
    parser.add_argument("--no-entropy", action="store_true", help="Disable entropy-based detection; signatures only.")
    parser.add_argument(
        "--entropy-threshold", type=float, default=4.3,
        help="Minimum Shannon entropy (bits/char) for a base64-like token to be flagged (default: 4.3).",
    )
    parser.add_argument("--ignore-file", type=Path, help="Path to a .secretscanignore file (default: <path>/.secretscanignore if present).")
    parser.add_argument("--json-out", type=Path, help="Write the full JSON report to this path.")
    parser.add_argument("--markdown-out", type=Path, help="Write a Markdown report to this path.")
    parser.add_argument("--llm", action="store_true", help="Use an LLM (Claude) to write the triage narrative.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output.")
    parser.add_argument("--no-narrative", action="store_true", help="Skip the triage narrative section entirely.")
    return parser


def _resolve_allowlist(args) -> Allowlist:
    ignore_file = args.ignore_file or (args.path / ".secretscanignore")
    if ignore_file.exists():
        return load_allowlist_file(ignore_file)
    return Allowlist()


def run(args) -> dict:
    allowlist = _resolve_allowlist(args)
    entropy_config = None if args.no_entropy else EntropyConfig(base64_threshold=args.entropy_threshold)

    working_tree_findings = scan_working_tree(args.path, allowlist=allowlist, entropy_config=entropy_config)

    history_findings = []
    if args.git_history:
        history_findings = scan_git_history(
            args.path,
            allowlist=allowlist,
            entropy_config=entropy_config,
            since=args.since,
            max_commits=args.max_commits,
        )

    report = build_report(working_tree_findings, history_findings)
    report = filter_by_min_severity(report, args.min_severity)

    print(render_console(report, use_color=not args.no_color))

    if not args.no_narrative:
        print()
        print("--- Triage ---")
        print(get_summarizer(args.llm).summarize(report))

    if args.json_out:
        write_json(report, args.json_out)
    if args.markdown_out:
        write_markdown(report, args.markdown_out)

    return report


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        report = run(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    return EXIT_FINDINGS if report["summary"]["total_findings"] else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
