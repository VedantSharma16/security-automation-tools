"""Command line interface: scan, validate, coverage."""
from __future__ import annotations

import argparse
import json
import sys

from .condition import ConditionError
from .coverage import coverage, gaps
from .engine import Engine, read_events
from .matcher import MatchError
from .rule import RuleError, load_rules


def _load(path):
    try:
        return load_rules(path)
    except (RuleError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return None


def cmd_validate(args) -> int:
    rules = _load(args.rules)
    if rules is None:
        return 2
    try:
        Engine(rules)
    except ConditionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"OK: {len(rules)} rule(s) valid")
    return 0


def cmd_scan(args) -> int:
    rules = _load(args.rules)
    if rules is None:
        return 2
    try:
        matches = list(Engine(rules).scan(read_events(args.events)))
    except (ConditionError, MatchError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps([m.to_dict() for m in matches], indent=2))
    else:
        for m in matches:
            tech = ",".join(m.techniques) or "-"
            print(f"[{m.level.upper():<8}] {m.rule_title} (event #{m.event_index}, {tech})")
        print(f"{len(matches)} match(es) across {len(rules)} rule(s)")
    return 1 if matches else 0


def cmd_coverage(args) -> int:
    rules = _load(args.rules)
    if rules is None:
        return 2
    report = coverage(rules)
    if args.wanted:
        report["gaps"] = gaps(rules, args.wanted)
    if args.json:
        print(json.dumps(report, indent=2))
        return 0
    print(f"{report['rules']} rule(s), {len(report['techniques'])} technique(s) covered")
    for t, titles in report["techniques"].items():
        print(f"  {t:<10} {'; '.join(titles)}")
    if report["tactics"]:
        print("tactics: " + ", ".join(f"{k}={v}" for k, v in report["tactics"].items()))
    if report["untagged_rules"]:
        print("untagged: " + "; ".join(report["untagged_rules"]))
    if args.wanted:
        print("gaps: " + (", ".join(report["gaps"]) or "none"))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sigmalite", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="parse rules and check conditions")
    v.add_argument("rules")
    v.set_defaults(fn=cmd_validate)
    s = sub.add_parser("scan", help="run rules over JSONL events (exit 1 on match)")
    s.add_argument("rules")
    s.add_argument("events")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_scan)
    c = sub.add_parser("coverage", help="ATT&CK coverage of a rule set")
    c.add_argument("rules")
    c.add_argument("--wanted", nargs="*", help="technique IDs you expect to cover")
    c.add_argument("--json", action="store_true")
    c.set_defaults(fn=cmd_coverage)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
