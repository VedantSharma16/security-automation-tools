"""Command-line interface for recon-agent."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import fixtures, report as report_mod
from .agent import DEFAULT_MAX_STEPS, DEFAULT_TIMEOUT, LLMPolicy, ReconAgent, deterministic_next_action
from .models import SEVERITY_RANK

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recon-agent",
        description="Agentic, read-only attack-surface recon: HTTPS/HTTP/TLS probing plus "
        "security-header analysis, for hosts you are authorized to assess.",
    )
    parser.add_argument("--target", required=True, help="Hostname to assess, e.g. example.com")
    parser.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="Confirm you are authorized to probe --target. Required unless --fixture is used.",
    )
    parser.add_argument(
        "--fixture",
        type=Path,
        help="Run against a canned JSON fixture instead of the live network "
        "(see examples/fixture_example.json). Skips the authorization check.",
    )
    parser.add_argument(
        "--llm", action="store_true", help="Let an LLM (Anthropic tool use) choose each next step."
    )
    parser.add_argument("--max-steps", type=int, default=DEFAULT_MAX_STEPS)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument(
        "--min-severity", choices=list(SEVERITY_RANK), default="info", help="Only report findings at or above this severity."
    )
    parser.add_argument("--json-out", type=Path, help="Write the full JSON report to this path.")
    parser.add_argument("--md-out", type=Path, help="Write a Markdown report to this path.")
    parser.add_argument("--no-color", action="store_true")
    return parser


def _filter_by_min_severity(report: dict, min_severity: str) -> dict:
    threshold = SEVERITY_RANK[min_severity]
    filtered = [f for f in report["findings"] if SEVERITY_RANK[f["severity"]] >= threshold]
    report = dict(report)
    report["findings"] = filtered
    report["finding_count"] = len(filtered)
    return report


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.fixture and not args.i_am_authorized:
        print(
            "error: pass --i-am-authorized to confirm you are authorized to probe "
            f"{args.target!r}, or --fixture to run against canned data instead.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    probe_url_fn = None
    probe_tls_fn = None
    if args.fixture:
        try:
            data = fixtures.load_fixture(args.fixture)
        except (OSError, ValueError) as exc:
            print(f"error: could not load fixture: {exc}", file=sys.stderr)
            return EXIT_ERROR
        probe_url_fn = fixtures.make_probe_url_fn(data)
        probe_tls_fn = fixtures.make_probe_tls_fn(data)

    policy = LLMPolicy() if args.llm else deterministic_next_action
    agent = ReconAgent(policy=policy, max_steps=args.max_steps)

    run_kwargs = {"timeout": args.timeout}
    if probe_url_fn is not None:
        run_kwargs["probe_url_fn"] = probe_url_fn
        run_kwargs["probe_tls_fn"] = probe_tls_fn

    state = agent.run(args.target, **run_kwargs)

    report = report_mod.build_report(state)
    report = _filter_by_min_severity(report, args.min_severity)

    print(report_mod.render_console(report, use_color=not args.no_color))

    if args.json_out:
        report_mod.write_json(report, args.json_out)
    if args.md_out:
        report_mod.write_markdown(report, args.md_out)

    return EXIT_FINDINGS if report["finding_count"] else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
