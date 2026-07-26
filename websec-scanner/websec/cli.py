"""Command-line interface for websec-scanner."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import report as report_mod
from .models import SEVERITY_RANK, Severity
from .scanner import DEFAULT_TIMEOUT, Scanner

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_SEVERITY_CHOICES = [s.value for s in Severity]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="websec-scanner",
        description="Authorized-use web application security scanner: "
        "security headers, cookie flags, sensitive-file exposure, "
        "technology fingerprinting, and (opt-in) active reflected-XSS / "
        "SQL-injection probes.",
    )
    parser.add_argument("target", help="Base URL to scan, e.g. https://example.com")
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Required. Confirms you own this target or have explicit written "
        "authorization to test it. The scan will refuse to run without this flag.",
    )
    parser.add_argument(
        "--active",
        action="store_true",
        help="Also crawl the site and run active reflected-XSS / SQL-injection "
        "probes against discovered parameters (non-destructive: reflection and "
        "error-message checks only). Off by default.",
    )
    parser.add_argument(
        "--max-pages", type=int, default=25, help="Max pages to crawl when --active is set (default: 25)."
    )
    parser.add_argument(
        "--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"Per-request timeout in seconds (default: {DEFAULT_TIMEOUT})."
    )
    parser.add_argument(
        "--min-severity",
        choices=_SEVERITY_CHOICES,
        default="info",
        help="Only display findings at or above this severity (default: info).",
    )
    parser.add_argument("--json-out", type=Path, help="Write the full JSON report to this path.")
    parser.add_argument("--md-out", type=Path, help="Write a Markdown report to this path.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.authorized:
        print(
            "Refusing to scan: pass --authorized to confirm you own this "
            "target or have explicit written authorization to test it.\n"
            "Only scan systems you are authorized to test.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    try:
        scanner = Scanner(
            args.target,
            active=args.active,
            max_pages=args.max_pages,
            timeout=args.timeout,
        )
        result = scanner.scan()
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    min_rank = SEVERITY_RANK[Severity(args.min_severity)]
    result.findings = [f for f in result.findings if SEVERITY_RANK[f.severity] >= min_rank]

    print(report_mod.to_console(result, use_color=not args.no_color))

    if args.json_out:
        args.json_out.write_text(report_mod.to_json(result))
        print(f"\nJSON report written to {args.json_out}")

    if args.md_out:
        args.md_out.write_text(report_mod.to_markdown(result))
        print(f"Markdown report written to {args.md_out}")

    return EXIT_FINDINGS if result.findings else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
