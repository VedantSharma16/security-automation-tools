"""Command-line interface for sigma-rule-tuner."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sigma_tuner.evaluator import load_events
from sigma_tuner.narrative import get_narrator
from sigma_tuner.report import build_report, render_markdown
from sigma_tuner.technique_kb import get_technique, list_techniques
from sigma_tuner.tuner import DEFAULT_PRECISION_THRESHOLD, DEFAULT_RECALL_THRESHOLD, tune
from sigma_tuner.yaml_dump import dump as yaml_dump

EXIT_CONVERGED = 0
EXIT_NOT_CONVERGED = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sigma-tuner",
        description="Tune MITRE ATT&CK-mapped Sigma detection rules against labeled sample telemetry.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list-techniques", help="List ATT&CK technique IDs available in the knowledge base.")

    tune_p = sub.add_parser("tune", help="Tune a rule for one technique against a labeled event file.")
    tune_p.add_argument("--technique", required=True, help="ATT&CK technique ID, e.g. T1110.")
    tune_p.add_argument("--events", required=True, type=Path, help="Path to a labeled JSONL event file.")
    tune_p.add_argument("--precision-threshold", type=float, default=DEFAULT_PRECISION_THRESHOLD)
    tune_p.add_argument("--recall-threshold", type=float, default=DEFAULT_RECALL_THRESHOLD)
    tune_p.add_argument("--max-iterations", type=int, default=None)
    tune_p.add_argument("--llm", action="store_true", help="Use Claude to write the analyst narrative.")
    tune_p.add_argument("--format", choices=["json", "markdown", "yaml"], default="json")
    tune_p.add_argument("--out", type=Path, help="Write output to this path instead of stdout.")

    return parser


def _run_tune(args: argparse.Namespace) -> int:
    technique = get_technique(args.technique)
    events = load_events(args.events)

    result = tune(
        args.technique,
        events,
        precision_threshold=args.precision_threshold,
        recall_threshold=args.recall_threshold,
        max_iterations=args.max_iterations,
    )

    narrator = get_narrator(args.llm)
    narrative = narrator.narrate(result, technique)
    report = build_report(result, args.technique, technique, narrative)

    if args.format == "json":
        output = json.dumps(report, indent=2)
    elif args.format == "markdown":
        output = render_markdown(report)
    else:
        output = yaml_dump(report["final_rule"])

    if args.out:
        args.out.write_text(output)
        print(f"wrote {args.format} report to {args.out}", file=sys.stderr)
    else:
        print(output)

    return EXIT_CONVERGED if result.converged else EXIT_NOT_CONVERGED


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "list-techniques":
            for tid in list_techniques():
                technique = get_technique(tid)
                print(f"{tid}: {technique['name']} [{', '.join(technique['tactics'])}]")
            return EXIT_CONVERGED
        if args.command == "tune":
            return _run_tune(args)
    except KeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    return EXIT_ERROR  # pragma: no cover - argparse enforces a valid subcommand


if __name__ == "__main__":
    sys.exit(main())
