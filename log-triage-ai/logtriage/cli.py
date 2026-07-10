"""Command-line entry point: `python -m logtriage.cli analyze <logfile>`."""

from __future__ import annotations

import argparse
import datetime
import json
import sys

from .ioc import extract_iocs
from .triage import AnthropicTriageClient, HeuristicTriageClient, TriageEngine, alert_to_dict


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logtriage",
        description="Detect and triage suspicious activity in auth.log-style logs.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze a log file and print a triage report.")
    analyze.add_argument("logfile", help="Path to an auth.log-style file, or '-' for stdin.")
    analyze.add_argument(
        "--year",
        type=int,
        default=None,
        help="Year to assume for timestamps (auth.log omits it). Defaults to the current year.",
    )
    analyze.add_argument(
        "--llm",
        action="store_true",
        help="Use Claude for narrative triage (requires ANTHROPIC_API_KEY). "
        "Falls back to the offline heuristic triage otherwise.",
    )
    analyze.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON instead of a formatted report.",
    )
    return parser


def _print_report(events, alerts, report, iocs) -> None:
    print(f"Parsed {len(events)} log events, {len(alerts)} alert(s) triggered.\n")

    if not alerts:
        print("No suspicious activity detected.")
        return

    print(f"Overall severity: {report.overall_severity.upper()}")
    print(f"Summary: {report.executive_summary}\n")

    print("Alerts:")
    for alert, triage_result in zip(alerts, report.alerts):
        print(f"  [{triage_result.severity.upper()}] {alert.title}")
        print(f"    MITRE ATT&CK: {alert.mitre_technique}")
        print(f"    Analyst notes: {triage_result.analyst_notes}")
        print()

    if report.recommended_actions:
        print("Recommended actions:")
        for action in report.recommended_actions:
            print(f"  - {action}")
        print()

    any_iocs = any(iocs.values())
    if any_iocs:
        print("Indicators of compromise found in raw log text:")
        for kind, values in iocs.items():
            if values:
                print(f"  {kind}: {', '.join(values)}")


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "analyze":
        if args.logfile == "-":
            lines = sys.stdin.readlines()
            raw_text = "".join(lines)
        else:
            with open(args.logfile, encoding="utf-8") as f:
                lines = f.readlines()
                raw_text = "".join(lines)

        year = args.year or datetime.datetime.now().year

        if args.llm:
            try:
                client = AnthropicTriageClient()
            except Exception as exc:
                print(f"warning: could not initialize Claude triage client ({exc}); "
                      "falling back to heuristic triage.", file=sys.stderr)
                client = HeuristicTriageClient()
        else:
            client = HeuristicTriageClient()

        engine = TriageEngine(triage_client=client, year=year)
        events, alerts, report = engine.analyze(lines)
        iocs = extract_iocs(raw_text)

        if args.json:
            output = {
                "event_count": len(events),
                "alerts": [alert_to_dict(a) for a in alerts],
                "report": report.model_dump(),
                "iocs": iocs,
            }
            print(json.dumps(output, indent=2))
        else:
            _print_report(events, alerts, report, iocs)

        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
