"""Command line interface: scan | test | validate | coverage."""

from __future__ import annotations

import argparse
import json
import sys

from .coverage import coverage
from .engine import Engine, read_events
from .rules import RuleError, load_rules
from .testing import run_rule_tests


def _cmd_scan(args) -> int:
    rules = load_rules(args.rules)
    src = sys.stdin if args.events == "-" else open(args.events, encoding="utf-8")
    with src:
        alerts = Engine(rules).run(read_events(src))
    if args.format == "json":
        print(json.dumps([a.to_dict() for a in alerts], indent=2, default=str))
    else:
        for a in alerts:
            tech = ",".join(a.techniques) or "-"
            extra = f" x{a.matched_events} {a.group}" if a.group else ""
            print(f"[{a.level.upper():8}] {a.rule_id} {a.title} ({tech}){extra}")
        print(f"\n{len(alerts)} alert(s) from {len(rules)} rule(s)")
    return 2 if alerts and args.fail_on_alert else 0


def _cmd_test(args) -> int:
    bad = 0
    for rule in load_rules(args.rules):
        res = run_rule_tests(rule)
        print(f"{'PASS' if res.ok else 'FAIL'} {res.rule_id} ({res.passed} cases)")
        for f in res.failures:
            print(f"     {f}")
        bad += not res.ok
    return 1 if bad else 0


def _cmd_validate(args) -> int:
    rules = load_rules(args.rules)
    print(f"OK: {len(rules)} rule(s) valid")
    return 0


def _cmd_coverage(args) -> int:
    cov = coverage(load_rules(args.rules))
    if args.format == "json":
        print(json.dumps(cov, indent=2))
        return 0
    print(f"{cov['rules']} rules, {len(cov['techniques'])} techniques")
    for tactic, techs in cov["by_tactic"].items():
        print(f"  {tactic:22} {', '.join(techs) or '-'}")
    if cov["missing_tactics"]:
        print("Gaps: " + ", ".join(cov["missing_tactics"]))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sigmalite", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="run rules over JSONL events")
    s.add_argument("--rules", required=True)
    s.add_argument("--events", required=True, help="JSONL file or - for stdin")
    s.add_argument("--format", choices=["text", "json"], default="text")
    s.add_argument("--fail-on-alert", action="store_true", help="exit 2 if any alert fires (CI use)")
    s.set_defaults(fn=_cmd_scan)
    t = sub.add_parser("test", help="run each rule's embedded tests")
    t.add_argument("--rules", required=True)
    t.set_defaults(fn=_cmd_test)
    v = sub.add_parser("validate", help="lint rule files")
    v.add_argument("--rules", required=True)
    v.set_defaults(fn=_cmd_validate)
    c = sub.add_parser("coverage", help="ATT&CK coverage from rule tags")
    c.add_argument("--rules", required=True)
    c.add_argument("--format", choices=["text", "json"], default="text")
    c.set_defaults(fn=_cmd_coverage)
    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except (RuleError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
