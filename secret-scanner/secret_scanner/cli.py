"""Command-line interface for secret-scanner.

    secret-scanner scan .                        # scan the working tree
    secret-scanner scan . --format sarif -o out.sarif
    secret-scanner history .                      # scan full git history
    secret-scanner scan . --baseline .secret-scanner-baseline.json
    secret-scanner scan . --create-baseline .secret-scanner-baseline.json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from secret_scanner.baseline import DEFAULT_BASELINE_FILENAME, Baseline
from secret_scanner.report import FORMATTERS, SEVERITY_ORDER
from secret_scanner.scanner import DEFAULT_EXCLUDE_DIRS, Finding, scan_git_history, scan_paths

_FAIL_ON_CHOICES = list(SEVERITY_ORDER) + ["none"]


def _severity_at_or_above(finding: Finding, threshold: str) -> bool:
    if threshold == "none":
        return False
    return SEVERITY_ORDER.get(finding.severity, 9) <= SEVERITY_ORDER.get(threshold, 0)


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        choices=sorted(FORMATTERS),
        default="text",
        help="Output format (default: text).",
    )
    parser.add_argument("-o", "--output", type=Path, default=None, help="Write report to a file instead of stdout.")
    parser.add_argument(
        "--baseline",
        type=Path,
        default=None,
        help="Baseline file of previously-accepted findings to suppress (fingerprint match).",
    )
    parser.add_argument(
        "--create-baseline",
        type=Path,
        default=None,
        metavar="PATH",
        help="Write all findings from this run to PATH as a new baseline, then exit 0.",
    )
    parser.add_argument(
        "--fail-on",
        choices=_FAIL_ON_CHOICES,
        default="medium",
        help="Minimum severity that causes a non-zero exit code (default: medium). Use 'none' to never fail.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secret-scanner", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan files/directories as they exist on disk right now.")
    scan_parser.add_argument("paths", nargs="*", default=["."], help="Files or directories to scan (default: .)")
    scan_parser.add_argument(
        "--exclude-dir",
        action="append",
        default=[],
        metavar="DIR",
        help="Additional directory name to skip (repeatable). Defaults already skip .git, node_modules, venv, etc.",
    )
    _add_common_args(scan_parser)

    history_parser = subparsers.add_parser("history", help="Scan every added line across the full git history.")
    history_parser.add_argument("repo", nargs="?", default=".", help="Path to the git repository (default: .)")
    history_parser.add_argument(
        "--max-commits",
        type=int,
        default=None,
        help="Only scan the N most recent commits (default: entire history).",
    )
    _add_common_args(history_parser)

    return parser


def _write_report(text: str, output: Path | None) -> None:
    if output is None:
        sys.stdout.write(text)
    else:
        output.write_text(text, encoding="utf-8")


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        exclude_dirs = DEFAULT_EXCLUDE_DIRS | frozenset(args.exclude_dir)
        findings = scan_paths([Path(p) for p in args.paths], exclude_dirs=exclude_dirs)
    elif args.command == "history":
        findings = scan_git_history(Path(args.repo), max_commits=args.max_commits)
    else:  # pragma: no cover - argparse enforces valid subcommands
        parser.error(f"unknown command {args.command!r}")
        return 2

    if args.create_baseline is not None:
        Baseline.from_findings(findings).save(args.create_baseline)
        sys.stderr.write(f"Wrote baseline with {len(findings)} entr{'y' if len(findings) == 1 else 'ies'} to {args.create_baseline}\n")
        return 0

    baseline_path = args.baseline or (Path(DEFAULT_BASELINE_FILENAME) if Path(DEFAULT_BASELINE_FILENAME).exists() else None)
    if baseline_path is not None:
        baseline = Baseline.load(baseline_path)
        findings = baseline.filter_findings(findings)

    formatter = FORMATTERS[args.format]
    _write_report(formatter(findings), args.output)

    should_fail = any(_severity_at_or_above(f, args.fail_on) for f in findings)
    return 1 if should_fail else 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
