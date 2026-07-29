"""Command-line interface for Secret Sentinel."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .baseline import apply_allowlist, load_allowlist, save_allowlist
from .gitscan import GitScanError, scan_git_history
from .llm_triage import LLMTriageClient, triage_findings
from .patterns import SEVERITIES, load_signatures
from .report import build_report, filter_by_min_severity, render_console, write_json
from .scanner import scan_path

DEFAULT_PATTERNS_PATH = Path(__file__).resolve().parent.parent / "rules" / "default_patterns.yaml"

# Exit codes let this tool slot into pre-commit hooks / CI pipelines that
# want to fail a build when a secret is found.
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret-sentinel",
        description="Scan a directory tree (or its git history) for hardcoded "
        "secrets using signature matching, entropy analysis, and optional LLM triage.",
    )
    parser.add_argument("path", nargs="?", default=".", help="File or directory to scan (default: .)")
    parser.add_argument(
        "--rules", type=Path, default=DEFAULT_PATTERNS_PATH, help="Path to a YAML signature file."
    )
    parser.add_argument(
        "--min-severity", choices=SEVERITIES, default="low",
        help="Only report findings at or above this severity (default: low).",
    )
    parser.add_argument("--json-out", type=Path, help="Write the full JSON report to this path.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output.")
    parser.add_argument(
        "--allowlist", type=Path,
        help="JSON file of accepted-finding fingerprints to suppress on future scans.",
    )
    parser.add_argument(
        "--update-allowlist", action="store_true",
        help="Write this scan's findings to --allowlist instead of filtering against it.",
    )
    parser.add_argument(
        "--git-history", nargs="?", type=int, const=0, default=None, metavar="MAX_COMMITS",
        help="Scan git history (via 'git log -p') instead of the working tree. "
        "Optionally limit to the last MAX_COMMITS commits.",
    )
    parser.add_argument(
        "--llm", action="store_true",
        help="Send ambiguous (low/medium-confidence) findings to an LLM for true/false-positive triage.",
    )
    parser.add_argument(
        "--entropy-threshold", type=float, default=3.5,
        help="Minimum Shannon entropy (bits/char) for the generic detector to flag a value (default: 3.5).",
    )
    parser.add_argument(
        "--min-secret-length", type=int, default=12,
        help="Minimum candidate value length for the generic entropy detector (default: 12).",
    )
    parser.add_argument(
        "--max-file-size", type=int, default=2_000_000,
        help="Skip files larger than this many bytes (default: 2000000).",
    )
    return parser


def _run(args) -> dict:
    signatures = load_signatures(args.rules)

    if args.git_history is not None:
        findings = scan_git_history(
            args.path,
            signatures,
            max_commits=args.git_history or None,
            entropy_threshold=args.entropy_threshold,
            min_length=args.min_secret_length,
        )
        scan_type = "git-history"
    else:
        findings = scan_path(
            args.path,
            signatures,
            entropy_threshold=args.entropy_threshold,
            min_length=args.min_secret_length,
            max_size=args.max_file_size,
        )
        scan_type = "filesystem"

    if args.allowlist and args.allowlist.exists() and not args.update_allowlist:
        allowlist = load_allowlist(args.allowlist)
        findings = apply_allowlist(findings, allowlist)

    if args.allowlist and args.update_allowlist:
        save_allowlist(findings, args.allowlist)

    verdicts = {}
    if args.llm:
        verdicts = triage_findings(findings, LLMTriageClient())

    report = build_report(findings, scan_type, targets=[str(args.path)])
    if verdicts:
        for f in report["findings"]:
            verdict = verdicts.get(f["fingerprint"])
            if verdict:
                f["llm_triage"] = verdict

    report = filter_by_min_severity(report, args.min_severity)

    print(render_console(report, use_color=not args.no_color))

    if args.json_out:
        write_json(report, args.json_out)

    return report


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        report = _run(args)
    except GitScanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    return EXIT_FINDINGS if report["finding_count"] else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
