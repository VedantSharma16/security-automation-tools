"""Command-line entry point: parse an nmap scan, correlate CVEs, and emit a report."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .cve_matcher import load_rules, match_hosts
from .llm_narrative import get_narrator
from .nmap_parser import parse_file
from .report import build_report, stamp_generated_at, to_json, to_markdown
from .scoring import score_matches

DEFAULT_CVE_DB = Path(__file__).resolve().parent.parent / "data" / "cve_db.json"


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="asm",
        description="Correlate an nmap XML scan against a local CVE/insecure-protocol "
        "rule database and produce a prioritized attack-surface report.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan an nmap XML file and produce a report.")
    scan.add_argument("scan_file", help="Path to an nmap XML file (`nmap -oX scan.xml`).")
    scan.add_argument(
        "--cve-db",
        default=str(DEFAULT_CVE_DB),
        help="Path to the vulnerability-rule JSON database (default: bundled data/cve_db.json).",
    )
    scan.add_argument(
        "--format", choices=["json", "markdown"], default="markdown", help="Output format."
    )
    scan.add_argument("--out", help="Write the report to this file instead of stdout.")
    scan.add_argument(
        "--llm",
        action="store_true",
        help="Use Claude to write the narrative section (requires ANTHROPIC_API_KEY).",
    )
    scan.add_argument(
        "--model", default="claude-sonnet-5", help="Model to use when --llm is set."
    )

    return parser


def run_scan(args: argparse.Namespace) -> int:
    scan_path = Path(args.scan_file)
    if not scan_path.is_file():
        print(f"error: no such file: {scan_path}", file=sys.stderr)
        return 1

    cve_db_path = Path(args.cve_db)
    if not cve_db_path.is_file():
        print(f"error: no such CVE database: {cve_db_path}", file=sys.stderr)
        return 1

    hosts = parse_file(scan_path)
    rules = load_rules(cve_db_path)
    matches = match_hosts(hosts, rules)
    scored = score_matches(matches)

    report = build_report(scan_path, hosts, scored)
    stamp_generated_at(report)

    narrator = get_narrator(args.llm, model=args.model)
    report["narrative"] = narrator.narrate(report)

    output = to_json(report) if args.format == "json" else to_markdown(report)

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
