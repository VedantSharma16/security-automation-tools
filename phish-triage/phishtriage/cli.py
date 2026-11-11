"""Command-line interface: ``phishtriage analyze`` and ``phishtriage eval``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analyzer import analyze_file
from .evaluate import evaluate, format_eval
from .narrative import DEFAULT_MODEL, TemplateNarrator, get_narrator
from .report import iocs_to_csv, to_json, to_markdown

VERDICT_RANK = {"clean": 0, "suspicious": 1, "malicious": 2}
EXIT_FLAGGED = 2


def _collect(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            files.extend(sorted(p.glob("*.eml")))
        elif p.is_file():
            files.append(p)
        else:
            raise FileNotFoundError(f"no such file or directory: {p}")
    return files


def _cmd_analyze(args: argparse.Namespace) -> int:
    try:
        files = _collect(args.paths)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not files:
        print("error: no .eml files found", file=sys.stderr)
        return 1

    narrator = get_narrator(args.llm, args.model)
    reports = []
    for f in files:
        report = analyze_file(f)
        try:
            report["narrative"] = narrator.narrate(report)
        except Exception as exc:  # network/API errors must never block triage
            print(f"note: LLM narrative failed ({exc}); using template", file=sys.stderr)
            report["narrative"] = TemplateNarrator().narrate(report)
        reports.append(report)

    if args.format == "json":
        output = to_json(reports[0] if len(reports) == 1 else reports)
    elif args.format == "csv":
        output = iocs_to_csv(reports)
    else:
        output = "\n---\n\n".join(to_markdown(r) for r in reports)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"wrote {args.format} report for {len(reports)} message(s) to {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(output)

    if args.fail_on:
        threshold = VERDICT_RANK[args.fail_on]
        if any(VERDICT_RANK[r["summary"]["verdict"]] >= threshold for r in reports):
            return EXIT_FLAGGED
    return 0


def _cmd_eval(args: argparse.Namespace) -> int:
    result = evaluate(args.corpus)
    print(json.dumps(result.to_dict(), indent=2) if args.json else format_eval(result))
    if args.min_recall is not None and result.recall < args.min_recall:
        print(f"recall {result.recall:.3f} below required {args.min_recall}", file=sys.stderr)
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishtriage",
                                     description="Explainable phishing email triage for SOC/IR.")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="analyze one or more .eml files (or directories of them)")
    a.add_argument("paths", nargs="+")
    a.add_argument("--format", choices=["md", "json", "csv"], default="md",
                   help="md: analyst report, json: machine-readable, csv: IOC list for blocklists")
    a.add_argument("--out", help="write output to a file instead of stdout")
    a.add_argument("--llm", action="store_true", help="write the summary with Claude (needs ANTHROPIC_API_KEY)")
    a.add_argument("--model", default=DEFAULT_MODEL)
    a.add_argument("--fail-on", choices=["suspicious", "malicious"],
                   help=f"exit {EXIT_FLAGGED} if any message reaches this verdict (for SOAR/pipeline use)")
    a.set_defaults(func=_cmd_analyze)

    e = sub.add_parser("eval", help="score detection quality on a labeled corpus (labels.json)")
    e.add_argument("corpus")
    e.add_argument("--json", action="store_true")
    e.add_argument("--min-recall", type=float, help="exit 1 if recall falls below this value")
    e.set_defaults(func=_cmd_eval)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
