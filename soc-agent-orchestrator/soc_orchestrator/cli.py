"""Command-line entry point: investigate a case directory end to end."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .agent import DEFAULT_MODEL, investigate


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-orchestrator",
        description="Agentic SOC investigation pipeline that orchestrates this repo's "
        "specialist security tools over a case's evidence files.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    inv = subparsers.add_parser("investigate", help="Investigate a case directory.")
    inv.add_argument("case_dir", help="Directory containing case evidence files.")
    inv.add_argument(
        "--description", default="", help="Free-text incident description for context."
    )
    inv.add_argument(
        "--llm",
        action="store_true",
        help="Use Claude to plan tool calls and narrate (requires ANTHROPIC_API_KEY).",
    )
    inv.add_argument(
        "--no-llm",
        action="store_true",
        help="Force the deterministic offline planner even if ANTHROPIC_API_KEY is set.",
    )
    inv.add_argument("--model", default=DEFAULT_MODEL, help="Model to use when --llm is set.")
    inv.add_argument("--format", choices=["json", "markdown"], default="markdown")
    inv.add_argument("--out", help="Write the report to this file instead of stdout.")

    return parser


def _to_markdown(report: dict) -> str:
    lines = [
        "# SOC Investigation Report",
        "",
        f"**Case:** {report['case_dir']}",
        f"**Overall severity:** {report['overall_severity'].upper()}",
        f"**Risk score:** {report['risk_score']}/100",
        "**Planner:** "
        + ("Claude agentic tool-use loop" if report["llm_backed"] else "deterministic offline planner"),
        f"**Generated:** {report['generated_at']}",
        "",
    ]
    if report["incident_description"]:
        lines += ["## Incident description", "", report["incident_description"], ""]

    lines += ["## Tools invoked", ""]
    for t in report["tools_invoked"]:
        status = "OK" if t["ok"] else f"FAILED ({t['error']})"
        suffix = f": {t['summary']}" if t["ok"] else ""
        lines.append(f"- **{t['tool']}** — {status}{suffix}")

    if report["mitre_techniques"]:
        lines += ["", "## MITRE ATT&CK techniques observed", ""]
        for t in report["mitre_techniques"]:
            name = f" {t['name']}" if t.get("name") else ""
            lines.append(f"- {t['id']}{name} ({t['tactic']}) — via {t['source']}")

    lines += ["", "## Recommended actions", ""]
    for a in report["recommended_actions"]:
        lines.append(f"- {a}")

    lines += ["", "## Narrative", "", report["narrative"]]
    return "\n".join(lines)


def run_investigate(args: argparse.Namespace) -> int:
    case_dir = Path(args.case_dir)
    if not case_dir.is_dir():
        print(f"error: no such directory: {case_dir}", file=sys.stderr)
        return 1

    use_llm = None
    if args.no_llm:
        use_llm = False
    elif args.llm:
        use_llm = True

    report = investigate(
        case_dir=str(case_dir),
        incident_description=args.description,
        use_llm=use_llm,
        model=args.model,
    ).to_dict()

    output = json.dumps(report, indent=2) if args.format == "json" else _to_markdown(report)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
    else:
        print(output)

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "investigate":
        return run_investigate(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
