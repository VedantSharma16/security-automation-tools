"""Command-line entrypoint for the LLM red-team scanner.

Usage:
    llm-redteam scan --target demo-vulnerable
    llm-redteam scan --target demo-hardened --json
    llm-redteam scan --target demo-vulnerable --category LLM01,LLM06
    llm-redteam scan --target live --system-prompt-file my_bot_prompt.txt \\
        --secret-markers "SECRET-KEY-123"
    llm-redteam list-attacks
"""

from __future__ import annotations

import argparse
import json
import sys

from llm_redteam.attacks import ATTACKS, filter_attacks
from llm_redteam.judge import ResponseJudge
from llm_redteam.report import build_report, render_text
from llm_redteam.scanner import run_scan
from llm_redteam.target import DemoHardenedAssistant, DemoVulnerableAssistant, LiveAnthropicTarget

TARGET_FACTORIES = {
    "demo-vulnerable": lambda args: DemoVulnerableAssistant(),
    "demo-hardened": lambda args: DemoHardenedAssistant(),
}


def _build_live_target(args: argparse.Namespace):
    if not args.system_prompt_file:
        raise SystemExit("--target live requires --system-prompt-file <path>")
    with open(args.system_prompt_file, encoding="utf-8") as handle:
        system_prompt = handle.read()
    markers = tuple(m.strip() for m in (args.secret_markers or "").split(",") if m.strip())
    return LiveAnthropicTarget(system_prompt=system_prompt, secret_markers=markers)


def _build_target(args: argparse.Namespace):
    if args.target == "live":
        return _build_live_target(args)
    factory = TARGET_FACTORIES.get(args.target)
    if factory is None:
        raise SystemExit(f"Unknown target: {args.target!r}")
    return factory(args)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="llm-redteam",
        description="Run an adversarial prompt-injection / jailbreak test battery against an LLM-backed app.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run the attack battery against a target.")
    scan.add_argument(
        "--target",
        choices=["demo-vulnerable", "demo-hardened", "live"],
        default="demo-vulnerable",
        help="Which target to scan. 'live' calls a real Claude-backed system prompt.",
    )
    scan.add_argument("--system-prompt-file", help="Path to a system-prompt file (required for --target live).")
    scan.add_argument(
        "--secret-markers",
        help="Comma-separated confidential strings from the live target's system prompt, for leak detection.",
    )
    scan.add_argument(
        "--category",
        help="Comma-separated OWASP category codes to run, e.g. LLM01,LLM06. Default: all.",
    )
    scan.add_argument("--json", action="store_true", help="Output the full report as JSON.")

    subparsers.add_parser("list-attacks", help="List the attack library and exit.")

    return parser


def _run_scan(args: argparse.Namespace) -> int:
    target = _build_target(args)
    categories = tuple(args.category.split(",")) if args.category else None
    attacks = filter_attacks(categories)
    judge = ResponseJudge()
    findings = run_scan(target, attacks=attacks, judge=judge)
    report = build_report(getattr(target, "name", args.target), findings)

    if args.json:
        print(report.to_json())
    else:
        print(render_text(report))
        print(f"Judge LLM-backed refinement: {'yes' if judge.is_live else 'no (heuristic-only)'}")
    return 1 if report.severity in ("critical", "high") else 0


def _list_attacks() -> int:
    for attack in ATTACKS:
        print(f"{attack.id:30s} [{attack.category}] {attack.name}")
        print(f"{'':30s} technique={attack.technique} delivery={attack.delivery}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "list-attacks":
        return _list_attacks()
    return _run_scan(args)


if __name__ == "__main__":
    raise SystemExit(main())
