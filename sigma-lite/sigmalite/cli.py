"""Command line interface: run | validate | coverage."""
from __future__ import annotations

import argparse
import json
import sys

from . import engine, report
from .rules import RuleError, load_rules


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sigmalite", description="Sigma-style detection engine")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="evaluate rules against an event file (.jsonl or JSON array)")
    r.add_argument("rules")
    r.add_argument("events")
    r.add_argument("--json", action="store_true", help="emit JSON instead of text")
    r.add_argument("--fail-on", choices=["low", "medium", "high", "critical"],
                   help="exit 2 if any alert is at or above this level")
    v = sub.add_parser("validate", help="lint rules without running them")
    v.add_argument("rules")
    c = sub.add_parser("coverage", help="MITRE ATT&CK coverage of a rule set")
    c.add_argument("rules")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rules = load_rules(args.rules)
        if args.cmd == "validate":
            print(f"OK: {len(rules)} rule(s) valid")
            return 0
        if args.cmd == "coverage":
            print(json.dumps(report.coverage(rules), indent=2))
            return 0
        alerts = engine.run(rules, engine.read_events(args.events))
    except (RuleError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps({"summary": report.summarize(alerts),
                          "alerts": [a.to_dict() for a in alerts]}, indent=2))
    else:
        print(report.format_text(alerts), end="")
    if args.fail_on:
        from .rules import LEVELS
        floor = LEVELS.index(args.fail_on)
        if any(LEVELS.index(a.level) >= floor for a in alerts):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
