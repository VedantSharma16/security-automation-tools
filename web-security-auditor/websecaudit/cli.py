"""Command-line interface for web-security-auditor."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .fetcher import fetch as default_fetch
from .grading import GRADE_ORDER, meets_minimum_grade
from .report import build_report, render_console, write_json, write_markdown
from .scanner import analyze

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="web-security-auditor",
        description=(
            "Passively scan one or more URLs for missing security headers, weak "
            "cookie flags, and TLS misconfiguration, and grade the result. "
            "Only scan systems you own or are authorized to test."
        ),
    )
    parser.add_argument("urls", nargs="*", help="One or more URLs to scan.")
    parser.add_argument(
        "--input-file", type=Path, help="File with one URL per line (blank lines/# comments ignored)."
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds.")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Do not verify TLS certificates (for testing self-signed/internal hosts).",
    )
    parser.add_argument(
        "--no-tls-probe",
        action="store_true",
        help="Skip the direct TLS socket probe (protocol/cert-expiry checks).",
    )
    parser.add_argument(
        "--min-grade",
        choices=GRADE_ORDER,
        default="C",
        help="Exit non-zero if any scanned site's grade is below this (default: C).",
    )
    parser.add_argument("--json-out", type=Path, help="Write full JSON report(s) to this path.")
    parser.add_argument("--md-out", type=Path, help="Write a Markdown report to this path.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output.")
    return parser


def _collect_urls(args) -> list[str]:
    urls = list(args.urls)
    if args.input_file:
        for line in args.input_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    normalized = []
    for u in urls:
        if not u.startswith(("http://", "https://")):
            u = f"https://{u}"
        normalized.append(u)
    return normalized


def run(argv: list[str] | None = None, fetch=default_fetch) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    urls = _collect_urls(args)

    if not urls:
        parser.error("Provide at least one URL, or --input-file.")

    reports = []
    worst_grade_ok = True
    for url in urls:
        fetch_result = fetch(
            url,
            timeout=args.timeout,
            verify_tls=not args.insecure,
            probe_tls=not args.no_tls_probe,
        )
        result = analyze(fetch_result)
        report = build_report(result)
        reports.append(report)
        print(render_console(report, use_color=not args.no_color))
        print()
        if not meets_minimum_grade(report["grade"], args.min_grade):
            worst_grade_ok = False

    if args.json_out:
        write_json(reports if len(reports) > 1 else reports[0], args.json_out)
    if args.md_out:
        from .report import render_markdown

        md = "\n\n---\n\n".join(render_markdown(r) for r in reports)
        args.md_out.write_text(md, encoding="utf-8")

    if any(r["error"] for r in reports):
        return EXIT_ERROR
    if not worst_grade_ok:
        return EXIT_FINDINGS
    return EXIT_CLEAN


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
