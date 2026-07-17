"""Command-line entry point: python -m log_triage_agent.cli <logfile> [options]"""

from __future__ import annotations

import argparse
import sys

from log_triage_agent.detectors import DetectorConfig
from log_triage_agent.parser import parse_file
from log_triage_agent.report import to_json, to_markdown
from log_triage_agent.triage_agent import DeterministicTriageClient, TriageAgent, resolve_default_client


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-triage-agent",
        description="Detect SSH brute-force, account enumeration, and privilege escalation "
        "in auth logs, then summarize findings for a human analyst.",
    )
    parser.add_argument("logfile", help="Path to an auth.log / syslog-style file")
    parser.add_argument(
        "--format", choices=["markdown", "json"], default="markdown", help="Output format (default: markdown)"
    )
    parser.add_argument(
        "--window", type=int, default=10, help="Brute-force detection window in minutes (default: 10)"
    )
    parser.add_argument(
        "--threshold", type=int, default=5, help="Failed attempts within the window to flag brute force (default: 5)"
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Force the deterministic (offline) summarizer even if ANTHROPIC_API_KEY is set",
    )
    parser.add_argument("--year", type=int, default=None, help="Year to assume for timestamps lacking one")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    events = parse_file(args.logfile, assume_year=args.year)
    if not events:
        print(f"No recognizable auth log lines found in {args.logfile}", file=sys.stderr)
        return 1

    config = DetectorConfig(brute_force_window_minutes=args.window, brute_force_threshold=args.threshold)
    client = DeterministicTriageClient() if args.no_llm else resolve_default_client()
    agent = TriageAgent(client=client, config=config)
    report = agent.run(events)

    output = to_json(report) if args.format == "json" else to_markdown(report)
    print(output)

    return 3 if report.highest_severity() and report.highest_severity().value == "critical" else 0


if __name__ == "__main__":
    raise SystemExit(main())
