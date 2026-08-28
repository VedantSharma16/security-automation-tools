"""Command-line entrypoint for the web recon agent.

Usage:
    recon-agent http://localhost:8000
    recon-agent https://example.com --i-am-authorized
    recon-agent https://example.com --i-am-authorized --json
    recon-agent https://example.com --i-am-authorized --llm-planner
"""

from __future__ import annotations

import argparse
import json
import sys
from urllib.parse import urlparse

from recon_agent.agent import run_agent
from recon_agent.planner import DeterministicPlanner, LLMPlanner
from recon_agent.report import ReconReport, build_report
from recon_agent.tools import ToolBox

_SEVERITY_ICONS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
}

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _require_authorization(target: str, authorized: bool) -> None:
    host = urlparse(target).hostname or ""
    if host in _LOCAL_HOSTS or authorized:
        return
    raise SystemExit(
        "Refusing to run active reconnaissance against a non-local target without "
        "--i-am-authorized. Only point this tool at systems you own or are explicitly "
        "authorized to test."
    )


def render_human(report: ReconReport) -> str:
    icon = _SEVERITY_ICONS.get(report.severity, "")
    lines = [
        f"{icon} Overall risk: {report.severity.upper()}",
        f"Planner: {report.planner}",
        f"LLM-backed narrative: {'yes' if report.llm_backed else 'no (offline heuristic fallback)'}",
        f"Finished: {report.finished_reason}",
        "",
        "Steps performed:",
    ]
    for step in report.transcript_summary:
        lines.append(f"  - {step}")

    lines += ["", f"Findings ({len(report.findings)}):"]
    if report.findings:
        for finding in report.findings:
            lines.append(f"  - [{finding.severity}] {finding.category}: {finding.summary}")
    else:
        lines.append("  (none)")

    lines += ["", "Narrative:", report.narrative]
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recon-agent",
        description="Agentic, tool-calling assistant for authorized web-application reconnaissance.",
    )
    parser.add_argument("target", help="Base target URL, e.g. https://example.com")
    parser.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="Confirm you have explicit authorization to actively probe this target. "
        "Required for anything other than localhost.",
    )
    parser.add_argument(
        "--llm-planner",
        action="store_true",
        help="Let Claude choose each next step dynamically (requires ANTHROPIC_API_KEY). "
        "Falls back to the deterministic planner if no key is configured.",
    )
    parser.add_argument("--max-steps", type=int, default=8, help="Agent step budget (default: 8).")
    parser.add_argument("--json", action="store_true", help="Output the full report as JSON.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    _require_authorization(args.target, args.i_am_authorized)

    planner = None
    if args.llm_planner:
        candidate = LLMPlanner(args.target)
        if candidate.is_live:
            planner = candidate
        else:
            print(
                "warning: --llm-planner requested but ANTHROPIC_API_KEY is not usable; "
                "falling back to the deterministic planner.",
                file=sys.stderr,
            )
    if planner is None:
        planner = DeterministicPlanner(args.target)

    run = run_agent(args.target, ToolBox(), planner, max_steps=args.max_steps)
    report = build_report(run)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(render_human(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
