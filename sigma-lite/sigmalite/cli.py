from __future__ import annotations

import argparse
import json
import sys

from .engine import coverage, read_events, scan
from .rules import LEVELS, RuleError, load_rules


def _scan(args) -> int:
    rules = load_rules(args.rules)
    with open(args.events, encoding="utf-8") if args.events != "-" else sys.stdin as fh:
        matches = scan(read_events(fh), rules, args.min_level)
    if args.json:
        print(json.dumps([{"rule_id": m.rule.id, "title": m.rule.title, "level": m.rule.level,
                           "techniques": m.rule.techniques, "line": m.line, "event": m.event}
                          for m in matches], indent=2))
    else:
        for m in sorted(matches, key=lambda m: (-LEVELS.index(m.rule.level), m.line)):
            tech = ",".join(m.rule.techniques) or "-"
            print(f"[{m.rule.level.upper():<8}] line {m.line:<4} {m.rule.title} ({m.rule.id}; {tech})")
        print(f"\n{len(matches)} match(es) from {len(rules)} rule(s)")
    return 1 if matches else 0


def _validate(args) -> int:
    rules = load_rules(args.rules)
    print(f"OK: {len(rules)} rule(s) valid")
    return 0


def _coverage(args) -> int:
    rules = load_rules(args.rules)
    for tech, ids in coverage(rules).items():
        print(f"{tech:<10} {', '.join(ids)}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sigmalite", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="run rules over a JSONL event file (exit 1 if any match)")
    s.add_argument("rules"), s.add_argument("events", help="JSONL file or '-' for stdin")
    s.add_argument("--min-level", choices=LEVELS, default="informational")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=_scan)
    v = sub.add_parser("validate", help="lint rules without scanning")
    v.add_argument("rules"), v.set_defaults(fn=_validate)
    c = sub.add_parser("coverage", help="MITRE ATT&CK technique coverage of a rule set")
    c.add_argument("rules"), c.set_defaults(fn=_coverage)
    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except (RuleError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
