"""Command-line entry point: run the agent against an alert JSON file."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .agent import DEFAULT_MODEL, SecOpsAgent
from .playbook import AlertCase
from .report import render_json, render_markdown


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Agentic SOC alert triage playbook runner.")
    parser.add_argument("--alert", required=True, type=Path, help="Path to a JSON alert file.")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--api-key", default=None, help="Overrides ANTHROPIC_API_KEY for this run.")
    args = parser.parse_args(argv)

    try:
        alert_data = json.loads(args.alert.read_text())
    except FileNotFoundError:
        print(f"error: alert file not found: {args.alert}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON in {args.alert}: {exc}", file=sys.stderr)
        return 1

    alert = AlertCase.from_dict(alert_data)
    agent = SecOpsAgent(api_key=args.api_key, model=args.model)
    report = agent.investigate(alert)

    if args.format == "json":
        print(render_json(report))
    else:
        print(render_markdown(report))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
