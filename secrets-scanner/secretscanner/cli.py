"""Command-line entry point for the secret scanner."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .gitscan import GitScanError, scan_git_history
from .patterns import SEVERITY_ORDER
from .report import build_report, to_json, to_markdown
from .scanner import scan_directory
from .triage import SecretTriageClient, triage_finding


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secretscanner",
        description="Scan a directory (and optionally its git history) for leaked credentials.",
    )
    scan = parser.add_argument_group("scan options")
    parser.add_argument("path", help="Path to the directory or git repository to scan.")
    scan.add_argument(
        "--history",
        action="store_true",
        help="Also scan git commit history (catches secrets removed from HEAD but still in past commits).",
    )
    scan.add_argument(
        "--history-only",
        action="store_true",
        help="Skip the working-tree scan and only scan git history (implies --history).",
    )
    scan.add_argument(
        "--max-commits", type=int, default=None, help="Limit history scan to the N most recent commits."
    )
    scan.add_argument(
        "--min-severity",
        choices=SEVERITY_ORDER,
        default="low",
        help="Only report findings at or above this severity (default: low, i.e. everything).",
    )
    parser.add_argument("--format", choices=["json", "markdown"], default="markdown", help="Output format.")
    parser.add_argument("--out", help="Write the report to this file instead of stdout.")
    parser.add_argument(
        "--llm", action="store_true", help="Use Claude to write the narrative section (requires ANTHROPIC_API_KEY)."
    )
    parser.add_argument("--model", default="claude-sonnet-5", help="Model to use when --llm is set.")

    return parser


def run_scan(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"error: no such path: {target}", file=sys.stderr)
        return 1

    min_rank = SEVERITY_ORDER.index(args.min_severity)

    working_tree_triaged = []
    if not args.history_only:
        for finding in scan_directory(target):
            if SEVERITY_ORDER.index(finding.severity) >= min_rank:
                working_tree_triaged.append(triage_finding(finding, source="working-tree"))

    history_entries = []
    if args.history or args.history_only:
        try:
            git_findings = scan_git_history(target, max_commits=args.max_commits)
        except GitScanError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        for gf in git_findings:
            if SEVERITY_ORDER.index(gf.finding.severity) >= min_rank:
                triaged = triage_finding(gf.finding, source="git-history")
                history_entries.append((triaged, gf))

    all_triaged = working_tree_triaged + [t for t, _ in history_entries]

    client = SecretTriageClient(use_llm=args.llm, model=args.model)
    if args.llm and not client.is_live:
        print(
            "note: --llm requested but ANTHROPIC_API_KEY is not set (or the 'anthropic' "
            "package is missing); falling back to the offline narrative.",
            file=sys.stderr,
        )
    narrative = client.narrate(all_triaged, target=str(target))

    report = build_report(str(target), working_tree_triaged, history_entries, narrative)
    output = to_json(report) if args.format == "json" else to_markdown(report)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
    else:
        print(output)

    has_genuine_findings = report["summary"]["likely_genuine"] > 0
    return 2 if has_genuine_findings else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    return run_scan(args)


if __name__ == "__main__":
    sys.exit(main())
