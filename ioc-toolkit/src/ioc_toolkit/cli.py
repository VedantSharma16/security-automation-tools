"""Command-line interface for the IOC toolkit.

Examples:
    ioc-toolkit extract report.txt
    ioc-toolkit extract report.txt --json
    cat report.txt | ioc-toolkit defang
    ioc-toolkit report report.txt --json
"""

from __future__ import annotations

import argparse
import json
import sys

from ioc_toolkit.defang import defang, refang
from ioc_toolkit.enrichment import enrich
from ioc_toolkit.extractor import extract
from ioc_toolkit.summarizer import get_summarizer


def _read_input(path: str | None) -> str:
    if path is None or path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _cmd_extract(args: argparse.Namespace) -> int:
    text = _read_input(args.file)
    result = extract(text)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
        return 0

    counts = result.to_dict()
    if not len(result):
        print("No IOCs found.")
        return 0
    for ioc_type, values in counts.items():
        if not values:
            continue
        print(f"[{ioc_type}] ({len(values)})")
        for v in values:
            print(f"  - {v}")
    return 0


def _cmd_defang(args: argparse.Namespace) -> int:
    text = _read_input(args.file)
    print(defang(text), end="" if text.endswith("\n") else "\n")
    return 0


def _cmd_refang(args: argparse.Namespace) -> int:
    text = _read_input(args.file)
    print(refang(text), end="" if text.endswith("\n") else "\n")
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    text = _read_input(args.file)
    extraction = extract(text)
    attack_hits = enrich(text)
    summary = get_summarizer().summarize(text, extraction, attack_hits)

    if args.json:
        payload = {
            "severity": summary.severity,
            "score": summary.score,
            "narrative": summary.narrative,
            "recommended_actions": summary.recommended_actions,
            "iocs": extraction.to_dict(),
            "attack_techniques": [
                {
                    "keyword": h.keyword,
                    "tactic": h.tactic,
                    "technique_id": h.technique_id,
                    "technique_name": h.technique_name,
                }
                for h in attack_hits
            ],
        }
        print(json.dumps(payload, indent=2))
        return 0

    print(f"Severity: {summary.severity.upper()} (score: {summary.score})")
    print(f"\n{summary.narrative}\n")
    if attack_hits:
        print("ATT&CK matches:")
        for h in attack_hits:
            print(f"  - {h.keyword}: {h.technique_name} ({h.technique_id or 'n/a'}) — {h.tactic}")
        print()
    counts = extraction.to_dict()
    if len(extraction):
        print("Indicators:")
        for ioc_type, values in counts.items():
            if values:
                print(f"  {ioc_type}: {len(values)}")
        print()
    print("Recommended actions:")
    for action in summary.recommended_actions:
        print(f"  - {action}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ioc-toolkit",
        description="Extract IOCs, map offensive tooling to ATT&CK, and triage threat reports/log excerpts.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_extract = subparsers.add_parser("extract", help="Extract IOCs from a file or stdin.")
    p_extract.add_argument("file", nargs="?", help="Path to input file; omit or use '-' to read stdin.")
    p_extract.add_argument("--json", action="store_true", help="Output as JSON.")
    p_extract.set_defaults(func=_cmd_extract)

    p_defang = subparsers.add_parser("defang", help="Defang IOCs in a file or stdin.")
    p_defang.add_argument("file", nargs="?", help="Path to input file; omit or use '-' to read stdin.")
    p_defang.set_defaults(func=_cmd_defang)

    p_refang = subparsers.add_parser("refang", help="Refang IOCs in a file or stdin.")
    p_refang.add_argument("file", nargs="?", help="Path to input file; omit or use '-' to read stdin.")
    p_refang.set_defaults(func=_cmd_refang)

    p_report = subparsers.add_parser(
        "report", help="Full triage: extract IOCs, map ATT&CK techniques, and summarize."
    )
    p_report.add_argument("file", nargs="?", help="Path to input file; omit or use '-' to read stdin.")
    p_report.add_argument("--json", action="store_true", help="Output as JSON.")
    p_report.set_defaults(func=_cmd_report)

    return parser


def main(argv: list | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
