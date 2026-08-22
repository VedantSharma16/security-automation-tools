"""Command-line entrypoint for the SOC investigation agent.

Usage:
    soc-agent --file examples/sample_incident_malicious.json
    soc-agent --file examples/sample_incident_benign.json --json
    cat incident.json | soc-agent
    soc-agent --file examples/sample_incident_malicious.json --llm-planner
"""

from __future__ import annotations

import argparse
import json
import sys

from soc_agent.agent import InvestigationAgent
from soc_agent.llm_client import LLMClient
from soc_agent.models import Incident
from soc_agent.planner import DeterministicPlanner, LLMPlanner
from soc_agent.report import render_human
from soc_agent.tools import ToolRegistry


def _read_incident(args: argparse.Namespace) -> Incident:
    if args.file:
        with open(args.file, encoding="utf-8") as handle:
            data = json.load(handle)
    elif not sys.stdin.isatty():
        raw = sys.stdin.read().strip()
        data = json.loads(raw) if raw else {}
    else:
        raise SystemExit("No input provided. Pass --file <path> or pipe incident JSON via stdin.")
    return Incident.from_dict(data)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-agent",
        description="Autonomously investigate a security incident: adaptively call threat-intel, "
        "asset, baseline, and ATT&CK-mapping tools, then produce a severity verdict and narrative.",
    )
    parser.add_argument("--file", "-f", help="Path to a JSON incident file.")
    parser.add_argument("--json", action="store_true", help="Output the full report as JSON.")
    parser.add_argument(
        "--llm-planner",
        action="store_true",
        help="Let Claude choose each next tool call via tool-use, instead of the deterministic policy "
        "(requires ANTHROPIC_API_KEY; falls back to deterministic automatically otherwise).",
    )
    parser.add_argument("--max-steps", type=int, default=8, help="Safety cap on tool calls per investigation.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    incident = _read_incident(args)

    registry = ToolRegistry()
    llm_client = LLMClient()
    planner = LLMPlanner(registry, llm_client=llm_client) if args.llm_planner else DeterministicPlanner()

    agent = InvestigationAgent(tools=registry, planner=planner, llm_client=llm_client, max_steps=args.max_steps)
    report = agent.investigate(incident)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(render_human(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
