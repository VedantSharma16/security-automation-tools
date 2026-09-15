"""Command-line entrypoint for recon-agent.

Usage:
    recon-agent --target example.com --i-have-authorization
    recon-agent --target example.com --i-have-authorization --json-out report.json
    recon-agent --target example.com --i-have-authorization --no-subdomain-enum
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from recon_agent.agent import COMMON_PORTS, Planner, run_recon
from recon_agent.dns_recon import load_wordlist
from recon_agent.narrative import NarrativeWriter
from recon_agent.report import build_report

_SEVERITY_ICONS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "info": "⚪",
}

_DEFAULT_WORDLIST = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "wordlists", "subdomains_small.txt")


def _render_human(report_dict: dict) -> str:
    icon = _SEVERITY_ICONS.get(report_dict["overall_severity"], "")
    lines = [
        f"{icon} Overall severity: {report_dict['overall_severity'].upper()}  (risk score {report_dict['risk_score']}/100)",
        f"Target: {report_dict['target']}",
        f"Planner: {'LLM-driven' if report_dict['planner_live'] else 'offline deterministic policy'}",
        f"Steps taken: {' -> '.join(report_dict['steps_taken']) or '(none)'}",
        "",
        f"Findings ({len(report_dict['findings'])}):",
    ]
    if report_dict["findings"]:
        for f in report_dict["findings"]:
            icon = _SEVERITY_ICONS.get(f["severity"], "")
            lines.append(f"  {icon} [{f['category']}] {f['title']} — {f['detail']}")
    else:
        lines.append("  (none)")

    lines += ["", "Summary:", report_dict["narrative"]]
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recon-agent",
        description="Read-only, agentic attack-surface reconnaissance for AUTHORIZED security assessments only.",
    )
    parser.add_argument("--target", "-t", required=True, help="Hostname to assess (e.g. example.com). Do not pass a target you are not authorized to test.")
    parser.add_argument(
        "--i-have-authorization",
        action="store_true",
        help="Required. Confirms you have explicit authorization to run reconnaissance against --target.",
    )
    parser.add_argument("--no-subdomain-enum", action="store_true", help="Skip subdomain brute-forcing.")
    parser.add_argument("--wordlist", default=_DEFAULT_WORDLIST, help="Path to a subdomain wordlist (one label per line).")
    parser.add_argument("--subdomain-limit", type=int, default=None, help="Only try the first N wordlist entries.")
    parser.add_argument("--ports", default=None, help="Comma-separated port list to scan (default: a common-services list).")
    parser.add_argument("--timeout", type=float, default=3.0, help="Per-probe network timeout in seconds.")
    parser.add_argument("--max-steps", type=int, default=5, help="Maximum number of tool calls the agent may make.")
    parser.add_argument("--json-out", help="Write the full JSON report to this path in addition to printing it.")
    parser.add_argument("--json", action="store_true", help="Print the full report as JSON instead of the human-readable view.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if not args.i_have_authorization:
        print(
            "Refusing to run: pass --i-have-authorization to confirm you have explicit "
            "permission to run reconnaissance against this target. This tool is for "
            "authorized security assessments only.",
            file=sys.stderr,
        )
        return 2

    ports = COMMON_PORTS if not args.ports else [int(p.strip()) for p in args.ports.split(",")]
    wordlist = [] if args.no_subdomain_enum else load_wordlist(args.wordlist)

    run = run_recon(
        args.target,
        allow_subdomain_enum=not args.no_subdomain_enum,
        wordlist=wordlist,
        ports=ports,
        subdomain_limit=args.subdomain_limit,
        timeout=args.timeout,
        max_steps=args.max_steps,
        planner=Planner(),
    )

    report = build_report(run)
    report.narrative = NarrativeWriter().write(report.to_dict())
    report_dict = report.to_dict()

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump(report_dict, handle, indent=2)

    if args.json:
        print(json.dumps(report_dict, indent=2))
    else:
        print(_render_human(report_dict))

    return 1 if report.overall_severity in ("high", "critical") else 0


if __name__ == "__main__":
    raise SystemExit(main())
