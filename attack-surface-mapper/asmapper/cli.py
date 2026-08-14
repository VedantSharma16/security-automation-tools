"""argparse entry point: `python -m asmapper.cli <target>`."""

from __future__ import annotations

import argparse
import sys

from .fetcher import fetch
from .planner import DEFAULT_MODEL, Planner
from .report import build_report, render_console, write_json, write_markdown

AUTHORIZATION_BANNER = (
    "This tool performs live HTTP requests against the target. Only run it "
    "against systems you own or are explicitly authorized to test (a pentest "
    "engagement, a bug bounty program's in-scope assets, or your own "
    "infrastructure)."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="asmapper",
        description="Passive attack-surface reconnaissance for authorized security assessments. " + AUTHORIZATION_BANNER,
    )
    parser.add_argument("target", help="Base URL of the target, e.g. https://example.com")
    parser.add_argument(
        "--enable-exposure-checks",
        action="store_true",
        help="Also probe a curated list of commonly-exposed sensitive paths (.env, .git/config, backups, ...). "
        "Opt-in: performs extra live requests beyond the initial fetch.",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Force the deterministic offline planner even if ANTHROPIC_API_KEY is set.",
    )
    parser.add_argument("--api-key", default=None, help="Anthropic API key (defaults to $ANTHROPIC_API_KEY).")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Anthropic model to use for the agentic planner.")
    parser.add_argument("--json-out", default=None, help="Write the full JSON report to this path.")
    parser.add_argument("--md-out", default=None, help="Write a Markdown report to this path.")
    parser.add_argument(
        "--min-severity",
        default="info",
        choices=["info", "low", "medium", "high", "critical"],
        help="Only show console findings at or above this severity (does not affect the JSON/Markdown reports).",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color in console output.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    planner = Planner(
        api_key=args.api_key,
        model=args.model,
        allow_exposure_checks=args.enable_exposure_checks,
        force_offline=args.offline,
    )

    state = planner.run(args.target, fetch_fn=fetch)
    report = build_report(state)

    if args.json_out:
        write_json(report, args.json_out)
    if args.md_out:
        write_markdown(report, args.md_out)

    print(render_console(report, min_severity=args.min_severity, use_color=not args.no_color))

    rating = report["summary"]["rating"]
    return 1 if rating in ("high", "critical") else 0


if __name__ == "__main__":
    sys.exit(main())
