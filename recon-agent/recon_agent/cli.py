"""Command-line interface for recon-agent."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import report as report_mod
from .agent import run_recon
from .authorization import AuthorizationError, check_authorization
from .findings import evaluate

DEFAULT_WORDLIST_PATH = Path(__file__).resolve().parent.parent / "wordlists" / "common_subdomains.txt"

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def load_wordlist(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text().splitlines() if line.strip() and not line.startswith("#")]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recon-agent",
        description=(
            "Agentic recon pipeline: DNS/subdomain enumeration, port scanning, and "
            "HTTP/TLS fingerprinting, orchestrated by a Claude tool-use loop when "
            "ANTHROPIC_API_KEY is set, or by a deterministic offline pipeline otherwise."
        ),
    )
    parser.add_argument("target", help="Domain or IP address to reconnoiter.")
    parser.add_argument(
        "--i-have-authorization",
        action="store_true",
        help=(
            "Confirm you are authorized to test this target. Required for any target "
            "that doesn't resolve to a private/loopback address."
        ),
    )
    parser.add_argument(
        "--wordlist", type=Path, default=DEFAULT_WORDLIST_PATH, help="Subdomain wordlist, one entry per line."
    )
    parser.add_argument("--json-out", type=Path, help="Write the full JSON report to this path.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        check_authorization(args.target, confirmed=args.i_have_authorization)
    except AuthorizationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    try:
        wordlist = load_wordlist(args.wordlist)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    run = run_recon(args.target, wordlist=wordlist)
    findings = evaluate(args.target, run.open_ports, run.http_fingerprints)
    report = report_mod.build_report(run, findings)

    print(report_mod.render_console(report, use_color=not args.no_color))

    if args.json_out:
        report_mod.write_json(report, args.json_out)

    return EXIT_FINDINGS if findings else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
