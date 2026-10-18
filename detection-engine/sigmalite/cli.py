"""Command line interface: validate | scan | coverage."""
from __future__ import annotations

import argparse
import json
import sys

from .coverage import coverage, render
from .engine import read_jsonl, scan_events
from .rules import LEVELS, RuleError, load_rules


def _cmd_validate(args) -> int:
    rules = load_rules(args.rules)
    print(f"OK: {len(rules)} rule(s) valid")
    return 0


def _cmd_coverage(args) -> int:
    cov = coverage(load_rules(args.rules))
    print(json.dumps(cov, indent=2) if args.json else render(cov))
    return 0


def _cmd_scan(args) -> int:
    rules = load_rules(args.rules)
    with (sys.stdin if args.events == "-" else open(args.events, encoding="utf-8")) as fh:
        alerts = scan_events(rules, read_jsonl(fh), args.min_level)
    if args.json:
        print(json.dumps([a.to_dict() for a in alerts], indent=2))
    else:
        for a in alerts:
            tech = ",".join(a.techniques) or "-"
            print(f"[{a.level.upper():<8}] line {a.line:<4} {a.rule_id}  {a.title}  ({tech})")
        print(f"\n{len(alerts)} alert(s)")
    return 2 if alerts else 0  # non-zero exit lets CI gate on detections


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sigmalite", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="lint rules")
    v.add_argument("rules")
    v.set_defaults(fn=_cmd_validate)
    c = sub.add_parser("coverage", help="ATT&CK coverage of a rule set")
    c.add_argument("rules")
    c.add_argument("--json", action="store_true")
    c.set_defaults(fn=_cmd_coverage)
    s = sub.add_parser("scan", help="run rules over JSONL events ('-' for stdin)")
    s.add_argument("rules")
    s.add_argument("events")
    s.add_argument("--min-level", choices=LEVELS, default="informational")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=_cmd_scan)
    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except (RuleError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
