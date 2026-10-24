"""Command line: validate / test / scan / coverage."""
from __future__ import annotations

import argparse
import json
import sys

from .engine import Engine, coverage, read_events
from .rule import LEVELS, RuleError, load_rules


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sigmalite", description=__doc__)
    p.add_argument("--rules", default="rules", help="rules directory (default: rules)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("validate", help="parse all rules")
    sub.add_parser("test", help="run each rule's embedded match/no_match tests")
    sub.add_parser("coverage", help="print MITRE ATT&CK technique coverage")
    s = sub.add_parser("scan", help="scan JSONL events (file or - for stdin)")
    s.add_argument("events")
    s.add_argument("--min-level", choices=LEVELS, default="informational")
    s.add_argument("--json", action="store_true", help="emit alerts as JSON lines")
    args = p.parse_args(argv)

    try:
        rules = load_rules(args.rules)
    except RuleError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    engine = Engine(rules)

    if args.cmd == "validate":
        print(f"OK: {len(rules)} rules loaded")
        return 0
    if args.cmd == "test":
        failures = engine.self_test()
        for f in failures:
            print("FAIL", f)
        print(f"{len(rules) - len({f.split(':')[0] for f in failures})}/{len(rules)} rules passed")
        return 1 if failures else 0
    if args.cmd == "coverage":
        for tech, ids in coverage(rules).items():
            print(f"{tech:<10} {', '.join(ids)}")
        return 0

    stream = sys.stdin if args.events == "-" else open(args.events)
    try:
        alerts = list(engine.scan(read_events(stream), args.min_level))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        if stream is not sys.stdin:
            stream.close()
    for a in alerts:
        if args.json:
            print(json.dumps(a.to_dict()))
        else:
            print(f"[{a.level.upper():<8}] line {a.line}: {a.title} ({', '.join(a.techniques) or 'no ATT&CK'})")
    print(f"{len(alerts)} alert(s)", file=sys.stderr)
    return 1 if alerts else 0


if __name__ == "__main__":
    sys.exit(main())
