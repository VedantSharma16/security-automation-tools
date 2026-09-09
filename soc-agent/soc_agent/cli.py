"""Command-line entry point: ``soc-agent investigate --alert ... [--logs ...]``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .agent import InvestigationIncomplete, SocAgent
from .report import exit_code_for, render_text, to_dict


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="soc-agent", description="Autonomous SOC triage agent.")
    sub = parser.add_subparsers(dest="command", required=True)

    investigate = sub.add_parser("investigate", help="Investigate a single alert.")
    investigate.add_argument("--alert", required=True, type=Path, help="Path to a text file containing the raw alert.")
    investigate.add_argument("--logs", type=Path, default=None, help="Optional path to a host log file the agent may search.")
    investigate.add_argument("--model", default=None, help="Override the Claude model used in live mode.")
    investigate.add_argument("--max-steps", type=int, default=8, help="Max tool-calling steps before giving up.")
    investigate.add_argument("--json-out", type=Path, default=None, help="Write the full structured report as JSON to this path.")
    investigate.add_argument("--no-transcript", action="store_true", help="Hide the tool-call transcript in the console report.")
    investigate.add_argument(
        "--fail-on-severity",
        default="high",
        choices=["low", "medium", "high", "critical"],
        help="Exit 1 if the verdict severity is at or above this level (default: high). Useful for CI gating.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "investigate":
        return _run_investigate(args)
    parser.error(f"Unknown command: {args.command}")
    return 2  # pragma: no cover - argparse exits before this


def _run_investigate(args: argparse.Namespace) -> int:
    try:
        alert_text = args.alert.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"error: could not read alert file: {exc}", file=sys.stderr)
        return 2

    kwargs = {"max_steps": args.max_steps}
    if args.model:
        kwargs["model"] = args.model
    agent = SocAgent(**kwargs)

    try:
        verdict, transcript = agent.investigate(alert_text, log_path=str(args.logs) if args.logs else None)
    except InvestigationIncomplete as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    mode = "live" if agent.is_live else "offline"
    print(render_text(verdict, transcript, mode=mode, show_transcript=not args.no_transcript))

    if args.json_out:
        report = to_dict(verdict, transcript, alert_text=alert_text, mode=mode)
        args.json_out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nWrote JSON report to {args.json_out}")

    return exit_code_for(verdict, args.fail_on_severity)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
