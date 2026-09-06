"""Command-line interface for codesec-agent.

Usage:
    codesec-agent path/to/project
    codesec-agent . --min-severity high --json-out report.json
    ANTHROPIC_API_KEY=sk-ant-... codesec-agent . --max-turns 10
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .agent import CodeSecurityAgent
from .report import filter_by_min_severity, render_console, write_json
from .rules import SEVERITIES

# Exit codes let this slot into CI as a security gate.
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codesec-agent",
        description="Agentic static-analysis code review: an LLM investigates a codebase via "
        "tool calls, with findings grounded in a deterministic rule engine.",
    )
    parser.add_argument("path", help="File or directory to review.")
    parser.add_argument(
        "--min-severity", choices=SEVERITIES, default="low", help="Only report findings at or above this severity."
    )
    parser.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        default="high",
        help="Exit non-zero if any finding at or above this severity is present (default: high).",
    )
    parser.add_argument("--json-out", type=Path, help="Write the full JSON report to this path.")
    parser.add_argument("--max-turns", type=int, default=8, help="Max tool-use turns for the live agent loop.")
    parser.add_argument("--json", action="store_true", help="Print the full report as JSON instead of text.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not Path(args.path).exists():
        print(f"error: '{args.path}' does not exist", file=sys.stderr)
        return EXIT_ERROR

    agent = CodeSecurityAgent(max_turns=args.max_turns)
    report = agent.review(args.path)
    report = filter_by_min_severity(report, args.min_severity)

    if args.json:
        import json as _json

        print(_json.dumps(report.to_dict(), indent=2))
    else:
        print(render_console(report))

    if args.json_out:
        write_json(report, args.json_out)

    fail_threshold = SEVERITIES.index(args.fail_on)
    has_blocking_finding = any(SEVERITIES.index(f.severity) >= fail_threshold for f in report.findings)
    return EXIT_FINDINGS if has_blocking_finding else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
