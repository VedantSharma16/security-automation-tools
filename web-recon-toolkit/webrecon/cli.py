"""Command-line entry point.

  webrecon scan <url>            live scan (network access required)
  webrecon analyze <fixture>     offline re-analysis of a captured HTTP transaction

For authorized security testing only: scan assets you own or have explicit
permission to test.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .llm_narrative import get_summarizer
from .pipeline import analyze as run_analyze
from .pipeline import scan as run_scan
from .report import to_json, to_markdown


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webrecon",
        description="Passive web recon and security-posture grading. Authorized targets only.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Live scan of a URL.")
    scan.add_argument("url", help="Target URL, e.g. https://example.com")
    scan.add_argument("--timeout", type=float, default=5.0, help="Network timeout in seconds.")
    scan.add_argument("--skip-tls", action="store_true", help="Skip the TLS certificate inspection stage.")
    _add_common_output_args(scan)

    analyze = subparsers.add_parser(
        "analyze", help="Offline analysis of a previously captured HTTP transaction (no network)."
    )
    analyze.add_argument("fixture", help="Path to a JSON fixture (see examples/).")
    _add_common_output_args(analyze)

    return parser


def _add_common_output_args(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument("--format", choices=["json", "markdown"], default="markdown", help="Output format.")
    subparser.add_argument("--out", help="Write the report to this file instead of stdout.")
    subparser.add_argument(
        "--llm", action="store_true", help="Use Claude to write the narrative section (requires ANTHROPIC_API_KEY)."
    )
    subparser.add_argument("--model", default="claude-sonnet-5", help="Model to use when --llm is set.")


def _emit(result: dict, args: argparse.Namespace) -> int:
    summarizer = get_summarizer(args.llm, model=args.model)
    result["narrative"] = summarizer.summarize(result)

    output = to_json(result) if args.format == "json" else to_markdown(result)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
    else:
        print(output)
    return 0


def run_scan_command(args: argparse.Namespace) -> int:
    if not args.url.lower().startswith(("http://", "https://")):
        print(f"error: unsupported URL scheme (only http/https are allowed): {args.url!r}", file=sys.stderr)
        return 1
    result = run_scan(args.url, timeout=args.timeout, skip_tls=args.skip_tls)
    return _emit(result, args)


def run_analyze_command(args: argparse.Namespace) -> int:
    fixture_path = Path(args.fixture)
    if not fixture_path.is_file():
        print(f"error: no such file: {fixture_path}", file=sys.stderr)
        return 1
    try:
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON in {fixture_path}: {exc}", file=sys.stderr)
        return 1

    result = run_analyze(fixture)
    return _emit(result, args)


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan_command(args)
    if args.command == "analyze":
        return run_analyze_command(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
