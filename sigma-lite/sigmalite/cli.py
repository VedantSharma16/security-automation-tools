from __future__ import annotations

import argparse
import json
import sys
from collections import Counter

from .engine import Engine, read_events
from .rule import LEVELS, RuleError, load_rules


def cmd_validate(a) -> int:
    try:
        rules = load_rules(a.rules)
    except RuleError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        return 2
    print(f"OK: {len(rules)} rule(s) valid")
    return 0


def cmd_scan(a) -> int:
    rules = load_rules(a.rules)
    matches = list(Engine(rules, a.min_level).scan(read_events(a.events)))
    if a.json:
        print(json.dumps([m.to_dict() for m in matches], indent=2))
    else:
        for m in sorted(matches, key=lambda m: (-LEVELS.index(m.rule.level), m.line)):
            tech = ",".join(m.rule.techniques) or "-"
            print(f"[{m.rule.level.upper():8}] line {m.line:<4} {m.rule.title} ({tech})")
        by_rule = Counter(m.rule.title for m in matches)
        print(f"\n{len(matches)} alert(s) across {len(by_rule)} rule(s)")
    return 1 if matches and a.fail_on_match else 0


def cmd_coverage(a) -> int:
    rules = load_rules(a.rules)
    cov: dict[str, list[str]] = {}
    for r in rules:
        for t in r.techniques:
            cov.setdefault(t, []).append(r.title)
    print(f"{len(rules)} rules cover {len(cov)} ATT&CK technique(s):")
    for t in sorted(cov):
        print(f"  {t:10} {'; '.join(cov[t])}")
    untagged = [r.title for r in rules if not r.techniques]
    if untagged:
        print("\nRules without ATT&CK technique tags:", ", ".join(untagged))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sigmalite", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="lint rule files"); v.add_argument("rules"); v.set_defaults(fn=cmd_validate)
    s = sub.add_parser("scan", help="run rules over JSON/JSONL events")
    s.add_argument("rules"); s.add_argument("events")
    s.add_argument("--min-level", choices=LEVELS, default="informational")
    s.add_argument("--json", action="store_true")
    s.add_argument("--fail-on-match", action="store_true", help="exit 1 if any alert (CI gating)")
    s.set_defaults(fn=cmd_scan)
    c = sub.add_parser("coverage", help="ATT&CK technique coverage of a rule set")
    c.add_argument("rules"); c.set_defaults(fn=cmd_coverage)
    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except (RuleError, ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
