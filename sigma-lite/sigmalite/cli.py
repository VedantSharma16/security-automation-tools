"""Command line interface: sigmalite validate|scan."""
from __future__ import annotations

import argparse
import json
import sys

from .engine import Engine, read_jsonl, summarize
from .rule import LEVELS, load_rules


def cmd_validate(args) -> int:
    rules, errors = load_rules(args.rules)
    for r in rules:
        print(f"OK   {r.level:<13} {r.title}  [{', '.join(r.attack_techniques) or '-'}]")
    for f, e in errors:
        print(f"FAIL {f}: {e}", file=sys.stderr)
    print(f"{len(rules)} valid, {len(errors)} invalid")
    return 1 if errors else 0


def cmd_scan(args) -> int:
    rules, errors = load_rules(args.rules)
    for f, e in errors:
        print(f"warning: skipped {f}: {e}", file=sys.stderr)
    if not rules:
        print("error: no valid rules loaded", file=sys.stderr)
        return 2
    min_idx = LEVELS.index(args.min_level)
    rules = [r for r in rules if LEVELS.index(r.level) >= min_idx]
    with (sys.stdin if args.events == "-" else open(args.events, encoding="utf-8")) as fh:
        matches = list(Engine(rules).scan(read_jsonl(fh)))
    summary = summarize(matches)
    if args.json:
        json.dump({"summary": summary, "matches": [m.to_dict() for m in matches]}, sys.stdout, indent=2)
        print()
    else:
        for m in matches:
            techs = ",".join(m.rule.attack_techniques) or "-"
            print(f"[{m.rule.level.upper():<8}] line {m.line:<4} {m.rule.title} ({techs})")
        print(f"\n{summary['total_matches']} match(es); highest severity: {summary['highest_severity'] or 'none'}")
    return 1 if matches and args.fail_on_match else 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sigmalite", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="lint rule files")
    v.add_argument("rules")
    v.set_defaults(fn=cmd_validate)
    s = sub.add_parser("scan", help="run rules against JSONL events ('-' for stdin)")
    s.add_argument("rules")
    s.add_argument("events")
    s.add_argument("--min-level", choices=LEVELS, default="informational")
    s.add_argument("--json", action="store_true")
    s.add_argument("--fail-on-match", action="store_true", help="exit 1 if anything matches (CI use)")
    s.set_defaults(fn=cmd_scan)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
