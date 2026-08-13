"""Command-line interface for recon-agent."""

from __future__ import annotations

import argparse
import sys

from . import agent as agent_mod
from . import report as report_mod
from .llm_client import LLMPlanner, generate_narrative
from .safety import UnauthorizedTargetError, check_authorization
from .vuln_kb import VulnKnowledgeBase

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

BANNER = (
    "recon-agent — for AUTHORIZED security testing only. Only scan systems "
    "you own or have explicit written permission to test."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recon-agent",
        description="Agentic recon: a planner (Claude tool-use, or a deterministic offline "
        "fallback) decides which read-only recon tool to call next against an authorized "
        "target, then reports fingerprints and known-CVE matches.",
    )
    parser.add_argument("--target", required=True, help="Hostname or IP to recon.")
    parser.add_argument("--ports", help="Comma-separated port list to scan (default: curated top ports).")
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm you have explicit permission to test a non-private/non-loopback target.",
    )
    parser.add_argument(
        "--use-llm",
        action="store_true",
        help="Use the Claude tool-use planner instead of the deterministic planner "
        "(requires ANTHROPIC_API_KEY).",
    )
    parser.add_argument("--max-steps", type=int, default=agent_mod.MAX_STEPS_DEFAULT, help="Agent step budget.")
    parser.add_argument("--no-narrative", action="store_true", help="Skip the LLM/offline narrative summary.")
    parser.add_argument("--json-out", help="Write the full JSON report to this path.")
    parser.add_argument("--md-out", help="Write a Markdown report to this path.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output.")
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    print(BANNER, file=sys.stderr)

    try:
        check_authorization(args.target, args.authorized)
    except UnauthorizedTargetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    ports = [int(p.strip()) for p in args.ports.split(",")] if args.ports else None

    planner = None
    if args.use_llm:
        planner = LLMPlanner()
        if not planner.is_live:
            print(
                "warning: --use-llm given but no live Claude client (missing ANTHROPIC_API_KEY "
                "or the `anthropic` package); falling back to the deterministic planner.",
                file=sys.stderr,
            )
            planner = None

    try:
        run = agent_mod.run(
            args.target, ports=ports, planner=planner, kb=VulnKnowledgeBase(), max_steps=args.max_steps
        )
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    narrative = None if args.no_narrative else generate_narrative(run.to_dict())

    print(report_mod.render_console(run, narrative=narrative, use_color=not args.no_color))

    if args.json_out:
        report_mod.write_json(run, args.json_out, narrative=narrative)
    if args.md_out:
        with open(args.md_out, "w", encoding="utf-8") as fh:
            fh.write(report_mod.render_markdown(run, narrative=narrative))

    return EXIT_FINDINGS if run.vuln_matches else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
