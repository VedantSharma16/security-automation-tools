"""Command-line entrypoint for phish-forensics.

Usage:
    phish-forensics --eml suspicious.eml
    phish-forensics --eml suspicious.eml --json --json-out report.json
"""

from __future__ import annotations

import argparse
import json
import sys

from .authresults import parse_authentication_results
from .heuristics import run_all
from .narrative import NarrativeWriter
from .parser import parse_eml
from .report import build_report, to_markdown


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phish-forensics",
        description="Offline-first phishing email triage: header/auth analysis, IOC extraction, brand-impersonation detection.",
    )
    parser.add_argument("--eml", "-e", required=True, help="Path to a raw .eml file to analyze.")
    parser.add_argument("--json", action="store_true", help="Print the full report as JSON instead of Markdown.")
    parser.add_argument("--json-out", help="Write the full JSON report to this path in addition to printing it.")
    parser.add_argument("--no-narrative", action="store_true", help="Skip the analyst-narrative step entirely.")
    parser.add_argument("--model", default=None, help="Override the LLM model used for the narrative step.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        email = parse_eml(args.eml)
    except FileNotFoundError:
        print(f"No such file: {args.eml}", file=sys.stderr)
        return 2

    auth = parse_authentication_results(email.auth_results_headers)
    findings = run_all(email, auth)
    report = build_report(email, auth, findings)

    if not args.no_narrative:
        writer = NarrativeWriter(model=args.model) if args.model else NarrativeWriter()
        report["narrative"] = writer.write(report)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(to_markdown(report))

    highest = report["summary"]["highest_severity"]
    return 1 if highest in ("HIGH", "CRITICAL") else 0


if __name__ == "__main__":
    raise SystemExit(main())
