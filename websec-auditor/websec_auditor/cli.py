"""Command-line entry point for websec-auditor.

    websec-auditor scan https://example.com
    websec-auditor scan example.com --json report.json --check-well-known

Scope note: this tool performs the same kind of request a normal browser
makes (one GET request plus, optionally, a couple of standard, publicly
documented files like /robots.txt). It does not brute-force paths, guess
credentials, or attempt exploitation. Only scan hosts you own or are
explicitly authorized to test.
"""

from __future__ import annotations

import argparse
import sys

from .audit import run_audit
from .fetcher import DEFAULT_TIMEOUT
from .report import render_json, render_markdown

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_FAIL_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="websec-auditor",
        description="Passive web security posture auditor (headers, cookies, TLS, fingerprinting).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Audit a single URL.")
    scan.add_argument("url", help="Target URL, e.g. https://example.com")
    scan.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-request timeout in seconds.")
    scan.add_argument(
        "--check-well-known",
        action="store_true",
        help="Also fetch robots.txt and /.well-known/security.txt (standard, publicly documented paths).",
    )
    scan.add_argument("--skip-tls", action="store_true", help="Skip the TLS certificate/protocol check.")
    scan.add_argument("--json", metavar="PATH", help="Write the JSON report to PATH instead of stdout.")
    scan.add_argument("--markdown", metavar="PATH", help="Write the Markdown report to PATH instead of stdout.")
    scan.add_argument(
        "--fail-on",
        choices=_FAIL_SEVERITY_ORDER,
        default=None,
        help="Exit 1 if any finding at or above this severity is present (for CI gating).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _run_scan(args)

    parser.print_help()
    return EXIT_ERROR


def _run_scan(args: argparse.Namespace) -> int:
    try:
        result = run_audit(
            args.url,
            timeout=args.timeout,
            check_well_known=args.check_well_known,
            skip_tls=args.skip_tls,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(render_json(result))
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(result))
    if not args.json and not args.markdown:
        print(render_markdown(result))

    if result.fetch_error:
        return EXIT_ERROR

    if args.fail_on:
        threshold = _FAIL_SEVERITY_ORDER.index(args.fail_on)
        if any(_FAIL_SEVERITY_ORDER.index(f.severity) >= threshold for f in result.findings):
            return EXIT_FINDINGS

    return EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
