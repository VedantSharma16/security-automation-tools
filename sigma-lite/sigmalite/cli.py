"""Command line interface: validate | scan | coverage."""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .coverage import coverage
from .engine import read_events, scan, summarize
from .rule import LEVELS, load_rules


def _load(path: str):
    rules, errors = load_rules(path)
    for f, e in errors:
        print(f"[invalid] {f}: {e}", file=sys.stderr)
    return rules, errors


def cmd_validate(a) -> int:
    rules, errors = _load(a.rules)
    print(f"{len(rules)} valid rule(s), {len(errors)} invalid")
    return 1 if errors else 0


def cmd_scan(a) -> int:
    rules, errors = _load(a.rules)
    if errors and a.strict:
        return 2
    alerts = scan(rules, read_events(a.events), a.min_level)
    if a.json:
        print(json.dumps({"summary": summarize(alerts),
                          "alerts": [vars(x) for x in alerts]}, indent=2))
    else:
        for x in alerts:
            techs = ",".join(x.techniques) or "-"
            print(f"[{x.level.upper():<8}] line {x.line:<4} {x.title} ({techs})")
        s = summarize(alerts)
        print(f"\n{s['total']} alert(s) from {len(rules)} rule(s)")
    return 1 if alerts and a.fail_on_alert else 0


def cmd_coverage(a) -> int:
    rules, _ = _load(a.rules)
    cov = coverage(rules)
    if a.json:
        print(json.dumps(cov, indent=2))
        return 0
    print(f"{cov['rules']} rules covering {len(cov['techniques'])} technique(s)\n")
    for tac, techs in cov["tactics"].items():
        print(f"  {tac:<22} {', '.join(techs)}")
    print(f"\nTactic gaps: {', '.join(cov['tactic_gaps']) or 'none'}")
    if cov["untagged_rules"]:
        print(f"Rules without ATT&CK technique tags: {', '.join(cov['untagged_rules'])}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sigmalite", description=__doc__)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="check rules compile")
    v.add_argument("rules")
    v.set_defaults(fn=cmd_validate)
    s = sub.add_parser("scan", help="run rules against a JSONL event file")
    s.add_argument("rules")
    s.add_argument("events")
    s.add_argument("--min-level", choices=LEVELS, default="informational")
    s.add_argument("--json", action="store_true")
    s.add_argument("--strict", action="store_true", help="abort if any rule is invalid")
    s.add_argument("--fail-on-alert", action="store_true", help="exit 1 when alerts fire (CI use)")
    s.set_defaults(fn=cmd_scan)
    c = sub.add_parser("coverage", help="ATT&CK coverage of the rule set")
    c.add_argument("rules")
    c.add_argument("--json", action="store_true")
    c.set_defaults(fn=cmd_coverage)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
