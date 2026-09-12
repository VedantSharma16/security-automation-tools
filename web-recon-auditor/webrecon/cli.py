"""Command-line interface for web-recon-auditor."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .fetcher import Fetcher
from .llm_summarizer import LLMSummarizer
from .paths import load_path_rules
from .report import render
from .scanner import scan_target

# Exit codes mirror the rest of this repo's tools, so this can slot into the
# same CI/cron automation patterns.
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_AUTHORIZATION_PROMPT = (
    "web-recon-auditor sends live HTTP requests (and probes sensitive paths) "
    "against the target you specify. Only run this against systems you own "
    "or have explicit written authorization to test.\n"
    "Re-run with --authorized once you've confirmed that, or set "
    "WEBRECON_AUTHORIZED=1."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webrecon",
        description="Passive HTTP attack-surface recon: security headers, sensitive "
        "path exposure, and TLS posture, for an authorized pentest target.",
    )
    parser.add_argument("target", help="Target host or URL, e.g. example.com or https://example.com")
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm you are authorized to test this target. Required to run a scan.",
    )
    parser.add_argument(
        "--format", choices=["markdown", "json"], default="markdown", help="Report output format."
    )
    parser.add_argument("--out", type=Path, help="Write the report to this path instead of stdout.")
    parser.add_argument("--no-tls-check", action="store_true", help="Skip the TLS handshake check.")
    parser.add_argument(
        "--paths-file", type=Path, help="Use a custom sensitive-paths rule file instead of the bundled one."
    )
    parser.add_argument(
        "--no-verify-tls",
        action="store_true",
        help="Disable TLS certificate verification on requests (e.g. for a self-signed test target).",
    )
    parser.add_argument(
        "--llm", action="store_true", help="Generate an executive summary via Claude (needs ANTHROPIC_API_KEY)."
    )
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not (args.authorized or os.environ.get("WEBRECON_AUTHORIZED") == "1"):
        print(_AUTHORIZATION_PROMPT, file=sys.stderr)
        return EXIT_ERROR

    try:
        path_rules = load_path_rules(args.paths_file) if args.paths_file else None
        fetcher = Fetcher(verify_tls=not args.no_verify_tls)
        summarizer = LLMSummarizer() if args.llm else None

        report = scan_target(
            args.target,
            fetcher=fetcher,
            check_tls=not args.no_tls_check,
            path_rules=path_rules,
            summarizer=summarizer,
        )
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    rendered = render(report, args.format)
    if args.out:
        args.out.write_text(rendered, encoding="utf-8")
        print(f"Report written to {args.out}")
    else:
        print(rendered)

    return EXIT_FINDINGS if report.findings else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
