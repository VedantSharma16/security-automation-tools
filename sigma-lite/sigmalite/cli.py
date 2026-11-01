"""Command line interface: scan | test | coverage."""
from __future__ import annotations

import argparse
import json
import sys

from .engine import coverage, read_events, scan, self_test
from .rule import LEVELS, RuleError, load_rules


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sigmalite", description="Sigma-subset detection engine")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="run rules against a JSONL event file")
    s.add_argument("rules"); s.add_argument("events")
    s.add_argument("--min-level", choices=LEVELS, default="informational")
    s.add_argument("--json", action="store_true", help="emit JSON")
    t = sub.add_parser("test", help="run rules' embedded match/no_match test cases")
    t.add_argument("rules")
    c = sub.add_parser("coverage", help="MITRE ATT&CK coverage of a rule set")
    c.add_argument("rules"); c.add_argument("--json", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rules = load_rules(args.rules)
        if args.cmd == "scan":
            alerts = scan(rules, read_events(args.events), args.min_level)
            if args.json:
                print(json.dumps([a.to_dict() for a in alerts], indent=2))
            else:
                for a in alerts:
                    tech = ",".join(a.techniques) or "-"
                    print(f"[{a.level.upper():<8}] line {a.line:<4} {a.title} ({tech})")
                print(f"{len(alerts)} alert(s) from {len(rules)} rule(s)")
            return 1 if alerts else 0
        if args.cmd == "test":
            fails = self_test(rules)
            for f in fails:
                print("FAIL", f)
            print(f"{len(rules) - len({f.split(':')[0] for f in fails})}/{len(rules)} rules passed")
            return 1 if fails else 0
        cov = coverage(rules)
        if args.json:
            print(json.dumps(cov, indent=2))
        else:
            print(f"{cov['rules']} rules, {len(cov['techniques'])} techniques")
            for tech, ids in cov["techniques"].items():
                print(f"  {tech:<10} {', '.join(ids)}")
            if cov["untagged_rules"]:
                print("Untagged:", ", ".join(cov["untagged_rules"]))
        return 0
    except (RuleError, ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
