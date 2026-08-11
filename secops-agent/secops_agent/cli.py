"""Command-line entry point: run a SecOps agent investigation and print the result."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .agent import DEFAULT_MAX_ITERATIONS, SecOpsAgent
from .planner import AnthropicPlanner, OfflinePlanner
from .tools import ToolRegistry

MALICIOUS_EXIT_CODE = 2


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secops-agent",
        description="Autonomous, tool-using SOC investigation agent (sandboxed, local-only tools).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    investigate = subparsers.add_parser("investigate", help="Run an investigation.")
    investigate.add_argument("--query", required=True, help="Natural-language investigation request.")
    investigate.add_argument("--log", help="Path to a log file the agent may search (optional).")
    investigate.add_argument(
        "--llm",
        action="store_true",
        help="Use the live Claude tool-use planner (requires ANTHROPIC_API_KEY). Default is offline.",
    )
    investigate.add_argument("--model", default="claude-sonnet-5", help="Model to use when --llm is set.")
    investigate.add_argument(
        "--max-iterations",
        type=int,
        default=DEFAULT_MAX_ITERATIONS,
        help="Maximum tool calls before the agent is forced to stop.",
    )
    investigate.add_argument("--format", choices=["text", "json"], default="text", help="Output format.")

    return parser


def run_investigate(args: argparse.Namespace) -> int:
    if args.log and not Path(args.log).is_file():
        print(f"error: no such file: {args.log}", file=sys.stderr)
        return 1

    planner = AnthropicPlanner(model=args.model) if args.llm else OfflinePlanner()
    tools = ToolRegistry(log_path=args.log)
    agent = SecOpsAgent(planner=planner, tools=tools, max_iterations=args.max_iterations)

    investigation = agent.investigate(args.query)

    if args.format == "json":
        payload = {
            "query": investigation.query,
            "verdict": investigation.verdict,
            "stopped_early": investigation.stopped_early,
            "final_report": investigation.final_report,
            "trace": [
                {"tool": r.tool, "arguments": r.arguments, "ok": r.ok, "output": r.output}
                for r in investigation.trace
            ],
        }
        print(json.dumps(payload, indent=2))
    else:
        print(f"Query: {investigation.query}\n")
        print("Trace:")
        for i, record in enumerate(investigation.trace, start=1):
            status = "ok" if record.ok else "error"
            print(f"  {i}. {record.tool}({record.arguments}) -> [{status}] {record.output}")
        print(f"\nVerdict: {investigation.verdict}")
        print(f"\nReport:\n{investigation.final_report}")

    return MALICIOUS_EXIT_CODE if investigation.verdict.startswith("malicious") else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "investigate":
        return run_investigate(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
