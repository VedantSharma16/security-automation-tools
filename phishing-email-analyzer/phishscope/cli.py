"""Command-line entry point.

    phishscope analyze suspicious.eml
    phishscope analyze reported_mail/ --format table --fail-on likely_phishing
    phishscope analyze msg.eml --format json --protect-domain acme-corp.com --llm
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .checks import AnalysisConfig
from .narrative import DEFAULT_MODEL, get_summarizer
from .parser import parse_file
from .report import analyze, to_json, to_markdown
from .scoring import VERDICT_BANDS

VERDICT_RANK = {v: i for i, (_, v) in enumerate(reversed(VERDICT_BANDS))}  # clean=0 .. malicious=3


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishscope", description="Explainable phishing email triage for .eml files."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    a = sub.add_parser("analyze", help="Analyze one or more .eml files or directories.")
    a.add_argument("paths", nargs="+", help=".eml files and/or directories containing them.")
    a.add_argument("--format", choices=["markdown", "json", "table"], default="markdown")
    a.add_argument("--out", help="Write output to this file instead of stdout.")
    a.add_argument(
        "--protect-domain", action="append", default=[], metavar="DOMAIN",
        help="Your organisation's domain(s); lookalikes of these are flagged. Repeatable.",
    )
    a.add_argument(
        "--fail-on", choices=list(VERDICT_RANK), default=None,
        help="Exit with status 2 if any message reaches this verdict (for pipelines).",
    )
    a.add_argument("--llm", action="store_true", help="Write the summary with Claude (needs ANTHROPIC_API_KEY).")
    a.add_argument("--model", default=DEFAULT_MODEL, help="Model used with --llm.")
    return parser


def collect_files(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            files.extend(sorted(p.glob("*.eml")))
        elif p.is_file():
            files.append(p)
        else:
            raise FileNotFoundError(p)
    return files


def render_table(reports: list[dict]) -> str:
    rows = [("VERDICT", "SCORE", "FINDINGS", "FILE", "SUBJECT")]
    for r in reports:
        s = r["summary"]
        rows.append((s["verdict"], str(s["risk_score"]), str(s["total_findings"]),
                     Path(r["source"]).name, r["message"]["subject"][:60]))
    widths = [max(len(row[i]) for row in rows) for i in range(4)]
    return "\n".join(
        "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row[:4])) + "  " + row[4]
        for row in rows
    ) + "\n"


def run_analyze(args: argparse.Namespace) -> int:
    try:
        files = collect_files(args.paths)
    except FileNotFoundError as exc:
        print(f"error: no such file or directory: {exc}", file=sys.stderr)
        return 1
    if not files:
        print("error: no .eml files found", file=sys.stderr)
        return 1

    cfg = AnalysisConfig(protected_domains=[d.lower() for d in args.protect_domain])
    summarizer = get_summarizer(args.llm, model=args.model)

    reports = []
    for path in files:
        report = analyze(parse_file(path), cfg, source=str(path))
        report["narrative"] = summarizer.summarize(report)
        reports.append(report)

    if args.format == "json":
        output = to_json(reports[0]) if len(reports) == 1 else json.dumps(reports, indent=2, ensure_ascii=False)
    elif args.format == "table":
        output = render_table(reports)
    else:
        output = "\n---\n\n".join(to_markdown(r) for r in reports)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output if output.endswith("\n") else output + "\n")

    if args.fail_on:
        threshold = VERDICT_RANK[args.fail_on]
        if any(VERDICT_RANK[r["summary"]["verdict"]] >= threshold for r in reports):
            return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if args.command == "analyze":
        return run_analyze(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
