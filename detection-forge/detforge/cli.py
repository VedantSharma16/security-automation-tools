from __future__ import annotations

import argparse
import json
import sys

from . import report
from .engine import RuleError, load_rules, read_events


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="detforge", description="Detection-as-code engine")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("validate", "test", "coverage"):
        p = sub.add_parser(name)
        p.add_argument("rules")
    sub.choices["coverage"].add_argument("--navigator", action="store_true", help="emit ATT&CK Navigator layer JSON")
    s = sub.add_parser("scan")
    s.add_argument("rules")
    s.add_argument("events", help="JSONL file")
    s.add_argument("--json", action="store_true")
    s.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], help="exit 2 if a hit at/above level")
    a = ap.parse_args(argv)

    try:
        rules = load_rules(a.rules)
    except (RuleError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if a.cmd == "validate":
        print(f"OK: {len(rules)} rules valid")
    elif a.cmd == "test":
        fails = [f for r in rules for f in r.self_test()]
        for f in fails:
            print("FAIL", f)
        print(f"{len(rules) - len({f.split(':')[0] for f in fails})}/{len(rules)} rules passed")
        return 1 if fails else 0
    elif a.cmd == "coverage":
        if a.navigator:
            print(json.dumps(report.navigator_layer(rules), indent=2))
        else:
            for t, ids in report.coverage(rules).items():
                print(f"{t:<12} {', '.join(ids)}")
    elif a.cmd == "scan":
        try:
            hits = report.scan(rules, read_events(a.events))
        except (RuleError, OSError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        if a.json:
            print(json.dumps({"summary": report.summarize(hits), "hits": hits}, indent=2))
        else:
            for h in sorted(hits, key=lambda h: -["informational", "low", "medium", "high", "critical"].index(h["level"])):
                print(f"[{h['level'].upper():<8}] event #{h['event_index']} {h['rule_id']} - {h['title']} {h['techniques']}")
            sm = report.summarize(hits)
            print(f"\n{sm['total']} hit(s); by level: {sm['by_level']}")
        if a.fail_on:
            order = ["low", "medium", "high", "critical"]
            if any(order.index(h["level"]) >= order.index(a.fail_on) for h in hits if h["level"] in order):
                return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
