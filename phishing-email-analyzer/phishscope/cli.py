"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .detectors import build_context, run_all_detectors
from .narrative import DEFAULT_MODEL, get_summarizer
from .parser import parse_file
from .report import build_report, to_json, to_markdown

EXIT_CODES = {"LIKELY_BENIGN": 0, "SUSPICIOUS": 2, "MALICIOUS": 3}


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishscope",
        description="Statically analyze a suspicious email (.eml) and produce a phishing triage report.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze one or more .eml files.")
    analyze.add_argument("emails", nargs="+", help="Path(s) to .eml files.")
    analyze.add_argument("--format", choices=["markdown", "json", "iocs"], default="markdown")
    analyze.add_argument("--out", help="Write output to this file instead of stdout.")
    analyze.add_argument("--brands", help="JSON file mapping brand -> [legitimate domains] to protect.")
    analyze.add_argument("--trusted-authserv", action="append", default=[], metavar="ID",
                         help="Only trust Authentication-Results stamped by this authserv-id (repeatable).")
    analyze.add_argument("--llm", action="store_true", help="Write the narrative with Claude (needs ANTHROPIC_API_KEY).")
    analyze.add_argument("--model", default=DEFAULT_MODEL, help="Claude model for --llm.")
    analyze.add_argument("--exit-code", action="store_true",
                         help="Exit 2 for SUSPICIOUS, 3 for MALICIOUS (for mail-pipeline / CI gating).")
    return parser


def analyze_file(path: Path, brands: dict | None, trusted: list[str], use_llm: bool, model: str) -> dict:
    email = parse_file(path)
    ctx = build_context(email, brands=brands, trusted_authserv_ids=trusted or None)
    findings = run_all_detectors(ctx)
    report = build_report(path, ctx, findings)
    report["narrative"] = get_summarizer(use_llm, model=model).summarize(report)
    return report


def run_analyze(args: argparse.Namespace) -> int:
    brands = None
    if args.brands:
        brands = json.loads(Path(args.brands).read_text(encoding="utf-8"))

    reports = []
    for raw in args.emails:
        path = Path(raw)
        if not path.is_file():
            print(f"error: no such file: {path}", file=sys.stderr)
            return 1
        reports.append(analyze_file(path, brands, args.trusted_authserv, args.llm, args.model))

    if args.format == "json":
        output = to_json(reports[0] if len(reports) == 1 else reports)
    elif args.format == "iocs":
        output = to_json({r["source"]: r["iocs"] for r in reports})
    else:
        output = "\n\n---\n\n".join(to_markdown(r) for r in reports)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
    else:
        print(output)

    if args.exit_code:
        return max(EXIT_CODES[r["verdict"]] for r in reports)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if args.command == "analyze":
        return run_analyze(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
