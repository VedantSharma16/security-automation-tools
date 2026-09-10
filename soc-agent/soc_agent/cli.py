"""Command-line entry point for the SOC triage agent.

Usage:
    python -m soc_agent.cli --evidence incident.txt
    python -m soc_agent.cli --evidence incident.txt --scan-processes
    python -m soc_agent.cli --evidence incident.txt --llm --format markdown
    python -m soc_agent.cli --scan-processes                     # live host only, no text evidence
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import tools
from .aggregator import build_report, recommended_actions
from .narrative import get_narrator
from .router import ROUTABLE_TOOLS, get_router

REPO_ROOT = Path(__file__).resolve().parents[2]

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-agent",
        description=(
            "Route freeform incident evidence to the right specialist security tool(s), "
            "run them, and produce one consolidated triage report."
        ),
    )
    parser.add_argument("--evidence", type=Path, help="Path to a file of freeform incident evidence text.")
    parser.add_argument(
        "--scan-processes",
        action="store_true",
        help="Also run process_threat_hunter against this host's live processes.",
    )
    parser.add_argument(
        "--min-process-severity",
        default="low",
        choices=["low", "medium", "high", "critical"],
        help="Minimum severity to include from the process scan (default: low).",
    )
    parser.add_argument("--force-log", action="store_true", help="Always run log_triage, overriding the router.")
    parser.add_argument("--force-ioc", action="store_true", help="Always run ioc_triage, overriding the router.")
    parser.add_argument("--skip-log", action="store_true", help="Never run log_triage, overriding the router.")
    parser.add_argument("--skip-ioc", action="store_true", help="Never run ioc_triage, overriding the router.")
    parser.add_argument(
        "--llm",
        action="store_true",
        help="Use Claude for routing and the narrative (requires ANTHROPIC_API_KEY); "
        "falls back to deterministic heuristics/templates without it.",
    )
    parser.add_argument("--model", default="claude-sonnet-5", help="Model to use when --llm is set.")
    parser.add_argument("--format", choices=["json", "markdown"], default="markdown", help="Output format.")
    parser.add_argument("--out", type=Path, help="Write the report to this file instead of stdout.")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help=argparse.SUPPRESS,  # override point for tests / non-standard checkouts
    )
    return parser


def resolve_decisions(args: argparse.Namespace, evidence_text: str | None) -> tuple[dict[str, bool], object | None]:
    """Combine the router's recommendation with any explicit --force/--skip flags."""
    if evidence_text is None:
        return {tool: False for tool in ROUTABLE_TOOLS}, None

    router = get_router(args.llm, model=args.model)
    decision = router.route(evidence_text)
    run_flags = {"log_triage": decision.run_log_triage, "ioc_triage": decision.run_ioc_triage}

    if args.force_log:
        run_flags["log_triage"] = True
    if args.force_ioc:
        run_flags["ioc_triage"] = True
    if args.skip_log:
        run_flags["log_triage"] = False
    if args.skip_ioc:
        run_flags["ioc_triage"] = False

    return run_flags, decision


def run_agent(args: argparse.Namespace) -> dict:
    evidence_text = None
    evidence_path = None
    if args.evidence:
        # Resolve to an absolute path: the tool subprocesses run with their own
        # project directory as cwd, so a relative path would no longer resolve.
        evidence_path = args.evidence.resolve()
        evidence_text = evidence_path.read_text(encoding="utf-8")

    run_flags, decision = resolve_decisions(args, evidence_text)

    results: dict[str, tools.ToolResult] = {}

    if run_flags["log_triage"]:
        results["log_triage"] = tools.run_log_triage(evidence_path, args.repo_root)
    else:
        results["log_triage"] = tools.skipped("log_triage", "not selected for this evidence")

    if run_flags["ioc_triage"]:
        results["ioc_triage"] = tools.run_ioc_triage(evidence_path, args.repo_root)
    else:
        results["ioc_triage"] = tools.skipped("ioc_triage", "not selected for this evidence")

    if args.scan_processes:
        results["process_hunter"] = tools.run_process_hunter(
            args.repo_root, min_severity=args.min_process_severity
        )
    else:
        results["process_hunter"] = tools.skipped("process_hunter", "not requested (pass --scan-processes)")

    report = build_report(results, decision, str(args.evidence) if args.evidence else None)
    narrator = get_narrator(args.llm, model=args.model)
    report["narrative"] = narrator.narrate(report)
    return report


def to_markdown(report: dict) -> str:
    lines = ["# SOC Triage Report", ""]
    lines.append(f"Generated: {report['generated_at']}")
    lines.append(f"Evidence source: {report['evidence_source'] or '(live host process scan only)'}")
    lines.append(f"Overall severity: **{report['overall_severity'].upper()}**")
    lines.append(f"Total findings: {report['total_findings']}")
    lines.append("")

    if report["router"]:
        lines.append("## Routing decision")
        lines.append("")
        lines.append(f"Mode: {report['router']['mode']}")
        for reason in report["router"]["reasoning"]:
            lines.append(f"- {reason}")
        lines.append("")

    lines.append("## Tool results")
    lines.append("")
    for name, result in report["tool_results"].items():
        if result["status"] == "ok":
            lines.append(f"- **{name}** [{result['severity']}]: {result['headline']}")
        elif result["status"] == "skipped":
            lines.append(f"- **{name}** (skipped): {result['headline']}")
        else:
            lines.append(f"- **{name}** (ERROR): {result['error']}")
    lines.append("")

    lines.append("## Recommended actions")
    lines.append("")
    for action in recommended_actions(report):
        lines.append(f"- {action}")
    lines.append("")

    if report.get("narrative"):
        lines.append("## Analyst Narrative")
        lines.append("")
        lines.append(report["narrative"])
        lines.append("")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if not args.evidence and not args.scan_processes:
        parser.error("provide --evidence <file>, --scan-processes, or both")

    if args.evidence and not args.evidence.is_file():
        print(f"error: no such file: {args.evidence}", file=sys.stderr)
        return EXIT_ERROR

    report = run_agent(args)
    output = json.dumps(report, indent=2) if args.format == "json" else to_markdown(report)

    if args.out:
        args.out.write_text(output, encoding="utf-8")
    else:
        print(output)

    if report["tools_errored"] and not report["tools_run"]:
        return EXIT_ERROR
    return EXIT_FINDINGS if report["total_findings"] else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
