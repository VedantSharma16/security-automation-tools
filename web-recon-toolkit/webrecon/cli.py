"""Command-line interface for webrecon."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .report import build_report, to_json, to_markdown
from .scanner import DEFAULT_DELAY, DEFAULT_TIMEOUT, AuthorizationError, InvalidTargetError, scan_target

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webrecon",
        description=(
            "Authorized-use web application reconnaissance: security-header "
            "audit, sensitive-file exposure discovery, and light tech "
            "fingerprinting."
        ),
    )
    parser.add_argument("target", help="Target base URL, e.g. https://example.com")
    parser.add_argument(
        "--i-have-authorization",
        action="store_true",
        dest="authorized",
        help=(
            "Required. Confirms you own this target or have explicit written "
            "permission to test it."
        ),
    )
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-request timeout, in seconds.")
    parser.add_argument(
        "--delay", type=float, default=DEFAULT_DELAY, help="Delay between path-discovery requests, in seconds."
    )
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--out", type=Path, help="Write the report to this file instead of stdout.")
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.authorized:
        print(
            "error: refusing to scan without --i-have-authorization.\n"
            "Only run webrecon against systems you own or have explicit "
            "written permission to test.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    try:
        result = scan_target(
            args.target, authorized=True, timeout=args.timeout, delay=args.delay
        )
    except (AuthorizationError, InvalidTargetError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    report = build_report(result)
    output = to_json(report) if args.format == "json" else to_markdown(report)

    if args.out:
        args.out.write_text(output, encoding="utf-8")
    else:
        print(output)

    if report["errors"]:
        return EXIT_ERROR
    return EXIT_FINDINGS if report["summary"]["total_findings"] else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
