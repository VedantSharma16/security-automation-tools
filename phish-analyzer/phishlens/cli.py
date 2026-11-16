"""Command-line interface.

    phishlens analyze message.eml [more.eml ...] [--format md|json] [--llm]
    phishlens iocs message.eml > blocklist.csv

Exit codes (``analyze``): 0 when every message is below ``--fail-on``,
1 when at least one meets it, 2 on usage / input errors. This makes the tool
usable as a gate in a mail-processing or SOAR pipeline.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analysis import VERDICTS, analyze
from .checks import Intel
from .narrative import get_narrator
from .parser import parse_file
from .report import iocs_csv, to_json, to_markdown

_VERDICT_RANK = {name: i for i, (_, name) in enumerate(reversed(VERDICTS))}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="phishlens", description="Static phishing email (.eml) analyzer.")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="Analyze one or more .eml files and print a triage report.")
    a.add_argument("files", nargs="+", type=Path)
    a.add_argument("--format", choices=("md", "json"), default="md")
    a.add_argument("--out", type=Path, help="Write the report to this file instead of stdout.")
    a.add_argument("--protect", action="append", default=[], metavar="DOMAIN",
                   help="Extra domain to protect from lookalikes (e.g. your company domain). Repeatable.")
    a.add_argument("--llm", action="store_true", help="Write the analyst note with Claude (needs ANTHROPIC_API_KEY).")
    a.add_argument("--model", default="claude-sonnet-5-5")
    a.add_argument("--fail-on", choices=[n for _, n in VERDICTS], default="likely_phishing",
                   help="Exit 1 if any message reaches this verdict (default: likely_phishing).")

    i = sub.add_parser("iocs", help="Export IOCs from .eml files as CSV.")
    i.add_argument("files", nargs="+", type=Path)
    i.add_argument("--protect", action="append", default=[], metavar="DOMAIN")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    intel = Intel.load(args.protect)

    reports = []
    for path in args.files:
        if not path.is_file():
            print(f"error: {path} is not a file", file=sys.stderr)
            return 2
        reports.append(analyze(parse_file(path), intel, source=path.name))

    if args.command == "iocs":
        rows = [iocs_csv(r).splitlines() for r in reports]
        sys.stdout.write("\n".join([rows[0][0]] + [line for r in rows for line in r[1:]]) + "\n")
        return 0

    narrator = get_narrator(args.llm, args.model)
    for r in reports:
        r["narrative"] = narrator.narrate(r)

    if args.format == "json":
        text = to_json(reports[0]) if len(reports) == 1 else json.dumps(reports, indent=2)
    else:
        text = "\n---\n\n".join(to_markdown(r) for r in reports)

    if args.out:
        args.out.write_text(text)
        print(f"report written to {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")

    threshold = _VERDICT_RANK[args.fail_on]
    return 1 if any(_VERDICT_RANK[r["summary"]["verdict"]] >= threshold for r in reports) else 0


if __name__ == "__main__":
    raise SystemExit(main())
