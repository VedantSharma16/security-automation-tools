"""Command-line entry point: scan a path and emit a report, with an optional CI gate."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from codesec import ast_scanner, secrets_scanner
from codesec.findings import ScanResult, Severity
from codesec.llm_advisor import get_advisor
from codesec.report import render
from codesec.secrets_scanner import iter_scannable_files


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codesec",
        description="Static security scanner: hardcoded secrets + insecure Python patterns.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan a file or directory.")
    scan.add_argument("path", help="File or directory to scan.")
    scan.add_argument("--format", choices=["text", "json"], default="text", help="Output format.")
    scan.add_argument("--out", help="Write the report to this file instead of stdout.")
    scan.add_argument(
        "--fail-on",
        choices=[s.name for s in Severity if s != Severity.INFO],
        default=None,
        help="Exit with status 1 if any finding meets or exceeds this severity "
        "(useful as a CI gate). Default: never fail.",
    )
    scan.add_argument(
        "--skip-secrets", action="store_true", help="Skip the hardcoded-secret detector."
    )
    scan.add_argument(
        "--skip-patterns", action="store_true", help="Skip the insecure-code-pattern detector."
    )
    scan.add_argument(
        "--llm",
        action="store_true",
        help="Use Claude to write the remediation narrative (requires ANTHROPIC_API_KEY).",
    )
    scan.add_argument("--model", default="claude-sonnet-5", help="Model to use when --llm is set.")

    return parser


def run_scan(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"error: no such file or directory: {target}", file=sys.stderr)
        return 2

    result = ScanResult()
    result.files_scanned = sum(1 for _ in iter_scannable_files(target)) if target.is_dir() else 1

    if not args.skip_secrets:
        for finding in secrets_scanner.scan_path(target):
            result.add(finding)
    if not args.skip_patterns:
        for finding in ast_scanner.scan_path(target):
            result.add(finding)

    report_dict = {
        "summary": {
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "total_findings": len(result.findings),
            "by_severity": result.count_by_severity(),
        },
        "findings": [f.to_dict() for f in result.sorted_findings()],
    }

    advisor = get_advisor(args.llm, model=args.model)
    narrative = advisor.advise(report_dict)

    output = render(result, args.format, narrative=narrative)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
    else:
        print(output)

    if args.fail_on:
        threshold = Severity.from_name(args.fail_on)
        max_sev = result.max_severity()
        if max_sev is not None and max_sev >= threshold:
            return 1

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
