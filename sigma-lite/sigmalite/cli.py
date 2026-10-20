"""Command line interface: ``sigmalite scan`` and ``sigmalite validate``."""
from __future__ import annotations

import argparse
import json
import sys

from .engine import evaluate, load_events, summarize
from .rules import LEVELS, RuleError, load_rules


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sigmalite", description="Run Sigma-style detection rules over JSON events.")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="evaluate rules against an event file")
    s.add_argument("--rules", required=True, help="rule file or directory")
    s.add_argument("--events", required=True, help="JSON array or NDJSON event file")
    s.add_argument("--min-level", choices=LEVELS, default="informational")
    s.add_argument("--format", choices=("text", "json"), default="text")
    v = sub.add_parser("validate", help="parse rules and report errors")
    v.add_argument("--rules", required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rules = load_rules(args.rules)
    except RuleError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if args.cmd == "validate":
        print(f"OK: {len(rules)} rule(s) valid")
        return 0
    try:
        events = load_events(args.events)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    matches = evaluate(rules, events, args.min_level)
    summary = summarize(matches)
    if args.format == "json":
        print(json.dumps(summary, indent=2))
    else:
        print(f"{len(events)} events, {len(rules)} rules -> {summary['total_matches']} match(es)")
        for h in summary["hits"]:
            ttp = ",".join(h["techniques"]) or "-"
            print(f"[{h['level'].upper():8}] {h['title']} ({ttp}) events={h['event_indexes']}")
    return 1 if matches else 0


if __name__ == "__main__":
    sys.exit(main())
