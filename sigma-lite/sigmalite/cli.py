"""Command line interface: scan, coverage, validate."""
from __future__ import annotations

import argparse
import json
import sys

from .coverage import coverage, render
from .engine import Engine, read_events
from .rule import LEVELS, RuleError, load_rules


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sigmalite", description="Sigma-style detection engine")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="evaluate rules against an NDJSON/JSON event file")
    s.add_argument("rules"), s.add_argument("events")
    s.add_argument("--min-level", choices=LEVELS, default="informational")
    s.add_argument("--json", action="store_true", help="emit JSON alerts")
    c = sub.add_parser("coverage", help="MITRE ATT&CK coverage of a rule set")
    c.add_argument("rules"), c.add_argument("--json", action="store_true")
    v = sub.add_parser("validate", help="check that rules parse")
    v.add_argument("rules")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rules = load_rules(args.rules)
        if args.cmd == "validate":
            print(f"OK: {len(rules)} rule(s) valid")
        elif args.cmd == "coverage":
            cov = coverage(rules)
            print(json.dumps(cov, indent=2) if args.json else render(cov))
        else:
            matches = list(Engine(rules, args.min_level).scan(read_events(args.events)))
            if args.json:
                print(json.dumps([{"rule": m.rule.id, "title": m.rule.title, "level": m.rule.level,
                                   "techniques": m.rule.techniques, "line": m.line,
                                   "event": m.event} for m in matches], indent=2))
            else:
                for m in matches:
                    print(f"[{m.rule.level.upper():<8}] {m.rule.title} "
                          f"(event #{m.line}; {', '.join(m.rule.techniques) or 'no technique'})")
                print(f"\n{len(matches)} alert(s)")
            return 1 if matches else 0
    except (RuleError, ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
