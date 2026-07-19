"""Command-line entrypoint for the IOC triage assistant.

Usage:
    ioc-triage --file examples/sample_alert.txt
    cat alert.txt | ioc-triage
    ioc-triage --file alert.txt --json
"""

from __future__ import annotations

import argparse
import json
import sys

from ioc_triage.triage import TriageReport, run_triage

_SEVERITY_ICONS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
}


def _read_alert_text(args: argparse.Namespace) -> str:
    if args.file:
        with open(args.file, encoding="utf-8") as handle:
            return handle.read()
    if not sys.stdin.isatty():
        return sys.stdin.read()
    raise SystemExit("No input provided. Pass --file <path> or pipe alert text via stdin.")


def _render_human(report: TriageReport) -> str:
    icon = _SEVERITY_ICONS.get(report.severity, "")
    lines = [
        f"{icon} Severity: {report.severity.upper()}",
        f"LLM-backed: {'yes' if report.llm_backed else 'no (offline heuristic fallback)'}",
        "",
        f"Indicators found ({len(report.indicators)}):",
    ]
    if report.indicators:
        for ioc in report.indicators:
            lines.append(f"  - [{ioc.category}] {ioc.value}")
    else:
        lines.append("  (none)")

    flagged = [e for e in report.enrichment if e.is_known_malicious]
    lines.append("")
    lines.append(f"Known-malicious hits ({len(flagged)}):")
    if flagged:
        for hit in flagged:
            lines.append(f"  - {hit.value} ({hit.category}) — {hit.confidence} confidence: {hit.notes}")
    else:
        lines.append("  (none)")

    lines.append("")
    lines.append("Matched ATT&CK techniques:")
    if report.matched_techniques:
        for technique, score in report.matched_techniques:
            lines.append(f"  - {technique.id} {technique.name} ({technique.tactic}) [relevance={score:.2f}]")
    else:
        lines.append("  (none)")

    lines.append("")
    lines.append("Summary:")
    lines.append(report.summary)
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ioc-triage",
        description="Extract IOCs from a security alert, enrich them, retrieve relevant "
        "ATT&CK context, and produce a triage summary.",
    )
    parser.add_argument("--file", "-f", help="Path to a file containing the raw alert/log text.")
    parser.add_argument("--json", action="store_true", help="Output the full report as JSON.")
    parser.add_argument("--top-k", type=int, default=3, help="Number of ATT&CK techniques to retrieve.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    alert_text = _read_alert_text(args)

    report = run_triage(alert_text, top_k_techniques=args.top_k)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(_render_human(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
