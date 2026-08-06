"""CLI entry point: recon-agent scan <target> --authorized [options]."""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import executor
from .report import to_json, to_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recon-agent",
        description="Passive attack-surface recon (DNS, HTTP headers, TLS, robots.txt) for authorized targets.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run a passive recon scan against a target.")
    scan.add_argument("target", help="Domain or hostname to assess, e.g. example.com")
    scan.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm you own this target or have explicit written permission to test it. Required.",
    )
    scan.add_argument(
        "--agentic",
        action="store_true",
        help="Let Claude choose which tools to run and write the summary (requires ANTHROPIC_API_KEY).",
    )
    scan.add_argument("--format", choices=["md", "json"], default="md")
    scan.add_argument("--out", help="Write the report to a file instead of stdout.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 1

    if not args.authorized:
        print(
            "Refusing to scan: pass --authorized to confirm you own this target or have "
            "explicit written permission to test it. This tool is for authorized security "
            "assessments only.",
            file=sys.stderr,
        )
        return 2

    report = executor.run(args.target, agentic=args.agentic)
    rendered = to_json(report) if args.format == "json" else to_markdown(report)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(rendered)
    else:
        print(rendered)

    return 1 if report.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
