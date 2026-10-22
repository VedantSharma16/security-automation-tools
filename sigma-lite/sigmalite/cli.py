"""Command line interface: validate | scan | coverage."""

from __future__ import annotations

import argparse
import json
import sys

from .coverage import coverage
from .engine import evaluate_events, read_events
from .rule import LEVELS, RuleError, load_rules


def _cmd_validate(args) -> int:
    try:
        rules = load_rules(args.rules)
    except RuleError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 2
    print(f"OK: {len(rules)} rule(s) valid")
    return 0


def _cmd_coverage(args) -> int:
    try:
        cov = coverage(load_rules(args.rules))
    except RuleError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(cov, indent=2))
        return 0
    print(f"{cov['rules']} rules, {len(cov['techniques'])} ATT&CK techniques")
    for tech, titles in cov["techniques"].items():
        print(f"  {tech:<10} {'; '.join(titles)}")
    if cov["untagged_rules"]:
        print("Rules without a technique tag: " + ", ".join(cov["untagged_rules"]))
    return 0


def _cmd_scan(args) -> int:
    try:
        rules = load_rules(args.rules)
        handle = sys.stdin if args.events == "-" else open(args.events, encoding="utf-8")
        with handle:
            events = list(read_events(handle.read()))
    except (RuleError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    matches = evaluate_events(rules, events, args.min_level)
    if args.json:
        print(json.dumps([m.to_dict() for m in matches], indent=2))
    else:
        print(f"Scanned {len(events)} event(s) with {len(rules)} rule(s): {len(matches)} alert(s)")
        for m in sorted(matches, key=lambda m: (-LEVELS.index(m.rule.level), m.line)):
            tech = ",".join(m.rule.techniques) or "-"
            print(f"  [{m.rule.level.upper():<8}] event #{m.line}: {m.rule.title} ({tech})")
    return 1 if matches and args.fail_on_match else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sigmalite", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="check rules compile")
    v.add_argument("rules")
    v.set_defaults(func=_cmd_validate)
    c = sub.add_parser("coverage", help="ATT&CK coverage of a rule set")
    c.add_argument("rules")
    c.add_argument("--json", action="store_true")
    c.set_defaults(func=_cmd_coverage)
    s = sub.add_parser("scan", help="run rules against JSON/JSONL events ('-' for stdin)")
    s.add_argument("rules")
    s.add_argument("events")
    s.add_argument("--min-level", choices=LEVELS, default="informational")
    s.add_argument("--json", action="store_true")
    s.add_argument("--fail-on-match", action="store_true", help="exit 1 if any alert fires (CI use)")
    s.set_defaults(func=_cmd_scan)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
