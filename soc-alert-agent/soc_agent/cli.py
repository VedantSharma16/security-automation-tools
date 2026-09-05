"""Command-line entrypoint for the SOC alert triage agent.

Usage:
    soc-agent --queue examples/sample_alerts.json
    soc-agent --queue examples/sample_alerts.json --alert-id ALT-1001
    soc-agent --queue examples/sample_alerts.json --llm
    soc-agent --queue examples/sample_alerts.json --json
"""

from __future__ import annotations

import argparse
import json
import sys

from .agent import run_agent
from .models import Alert
from .report import render_human
from .tools import ToolRegistry


def _load_queue(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-agent",
        description="Autonomously triage SOC alerts using a tool-calling agent loop.",
    )
    parser.add_argument(
        "--queue", "-q", default="examples/sample_alerts.json", help="Path to a JSON file containing an alert queue."
    )
    parser.add_argument("--alert-id", help="Only triage the alert with this alert_id (default: triage the whole queue).")
    parser.add_argument("--llm", action="store_true", help="Use the Anthropic-backed agent loop instead of the deterministic planner.")
    parser.add_argument("--model", default="claude-sonnet-5", help="Model to use with --llm.")
    parser.add_argument("--max-steps", type=int, default=8, help="Maximum tool-call steps per alert.")
    parser.add_argument("--json", action="store_true", help="Output results as JSON instead of a human-readable transcript.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    raw_alerts = _load_queue(args.queue)
    tools = ToolRegistry(alerts=raw_alerts)

    if args.alert_id:
        raw_alerts = [a for a in raw_alerts if a["alert_id"] == args.alert_id]
        if not raw_alerts:
            print(f"No alert with alert_id={args.alert_id!r} found in {args.queue}", file=sys.stderr)
            return 1

    results = []
    for raw in raw_alerts:
        alert = Alert.from_dict(raw)
        result = run_agent(alert, tools, use_llm=args.llm, model=args.model, max_steps=args.max_steps)
        results.append(result)

    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        print("\n\n".join(render_human(r) for r in results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
