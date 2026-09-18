"""Command-line entry point: score a vulnerability scan export and emit a
prioritized remediation report."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .enrichment import DEFAULT_EPSS_PATH, DEFAULT_KEV_PATH
from .llm_narrative import get_narrator
from .pipeline import prioritize
from .report import build_report, to_json, to_markdown


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnprioritize",
        description="Score a vulnerability scan export against EPSS, CISA KEV, and asset "
        "criticality to produce a ranked remediation report.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Score a scan export and produce a report.")
    scan.add_argument("scanfile", help="Path to the vulnerability scan export (CSV).")
    scan.add_argument("--assets", help="Path to a JSON asset inventory (hostname -> criticality/exposure).")
    scan.add_argument("--kev", default=str(DEFAULT_KEV_PATH), help="Path to a CISA KEV catalog JSON file.")
    scan.add_argument("--epss", default=str(DEFAULT_EPSS_PATH), help="Path to an EPSS scores JSON file.")
    scan.add_argument("--format", choices=["json", "markdown"], default="markdown", help="Output format.")
    scan.add_argument("--out", help="Write the report to this file instead of stdout.")
    scan.add_argument("--top", type=int, help="Limit the Markdown findings section to the top N.")
    scan.add_argument(
        "--llm", action="store_true", help="Use Claude to write the executive narrative (requires ANTHROPIC_API_KEY)."
    )
    scan.add_argument("--model", default="claude-sonnet-5", help="Model to use when --llm is set.")

    return parser


def run_scan(args: argparse.Namespace) -> int:
    scanfile = Path(args.scanfile)
    if not scanfile.is_file():
        print(f"error: no such file: {scanfile}", file=sys.stderr)
        return 1
    if args.assets and not Path(args.assets).is_file():
        print(f"error: no such file: {args.assets}", file=sys.stderr)
        return 1

    scored = prioritize(scanfile, args.assets, kev_path=args.kev, epss_path=args.epss)
    report = build_report(scanfile, args.assets, scored)

    narrator = get_narrator(args.llm, model=args.model)
    report["narrative"] = narrator.narrate(report)

    output = to_json(report) if args.format == "json" else to_markdown(report, top_n=args.top)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
    else:
        print(output)

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
