"""Command-line interface for Web Security Auditor."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .auditor import run_audit
from .llm_narrative import NarrativeClient
from .report import build_report, filter_by_min_severity, render_console, to_markdown, write_json

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_SEVERITIES = ["info", "low", "medium", "high", "critical"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="web-security-audit",
        description="Passive/lightweight-active recon of a web target: security "
        "headers, cookie flags, CORS policy, TLS config, and common sensitive-path "
        "exposure — mapped to OWASP Top 10 categories.",
    )
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument(
        "--min-severity",
        choices=_SEVERITIES,
        default="info",
        help="Only report findings at or above this severity (default: info).",
    )
    parser.add_argument("--json-out", type=Path, help="Write the full JSON report to this path.")
    parser.add_argument("--markdown-out", type=Path, help="Write a Markdown report to this path.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output.")
    parser.add_argument("--skip-tls", action="store_true", help="Skip the TLS certificate/protocol check.")
    parser.add_argument("--skip-cors", action="store_true", help="Skip the CORS misconfiguration probe.")
    parser.add_argument(
        "--skip-disclosure", action="store_true", help="Skip sensitive-path and robots.txt checks."
    )
    parser.add_argument(
        "--narrative",
        action="store_true",
        help="Generate an analyst narrative (LLM if ANTHROPIC_API_KEY is set, "
        "otherwise a deterministic offline summary).",
    )
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        findings = run_audit(
            args.url,
            skip_tls=args.skip_tls,
            skip_cors=args.skip_cors,
            skip_disclosure=args.skip_disclosure,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    report = build_report(args.url, findings)

    if args.narrative:
        client = NarrativeClient()
        report["narrative"] = client.summarize(args.url, report["findings"], report["summary"])

    report = filter_by_min_severity(report, args.min_severity)

    print(render_console(report, use_color=not args.no_color))

    if args.json_out:
        write_json(report, args.json_out)
    if args.markdown_out:
        args.markdown_out.write_text(to_markdown(report), encoding="utf-8")

    return EXIT_FINDINGS if report["findings"] else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
