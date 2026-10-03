"""Command line interface: ``sigmalite scan`` and ``sigmalite validate``."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter

from .engine import read_events, scan
from .rules import LEVELS, RuleError, load_rules


def _cmd_validate(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules)
    for r in rules:
        techniques = ",".join(r.attack_techniques) or "-"
        print(f"OK  {r.level:<13} {techniques:<12} {r.title}")
    print(f"{len(rules)} rule(s) valid")
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules)
    stream = sys.stdin if args.events == "-" else open(args.events, encoding="utf-8")
    with stream:
        events = list(read_events(stream))
    matches = list(scan(rules, events, min_level=args.min_level))

    if args.format == "json":
        print(json.dumps([m.to_dict() for m in matches], indent=2, default=str))
    else:
        for m in matches:
            techniques = ",".join(m.rule.attack_techniques) or "-"
            print(f"[{m.rule.level.upper():<8}] event #{m.index}  {m.rule.title}  (ATT&CK: {techniques})")
        by_level = Counter(m.rule.level for m in matches)
        summary = ", ".join(f"{by_level[l]} {l}" for l in reversed(LEVELS) if by_level[l]) or "none"
        print(f"\n{len(events)} events, {len(rules)} rules, {len(matches)} detections ({summary})")
    return 1 if matches and args.fail_on_match else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sigmalite", description="Lightweight Sigma rule engine.")
    sub = p.add_subparsers(dest="command", required=True)

    v = sub.add_parser("validate", help="compile rules and report problems")
    v.add_argument("rules", help="rule file or directory")
    v.set_defaults(func=_cmd_validate)

    s = sub.add_parser("scan", help="run rules against JSON/JSONL events")
    s.add_argument("rules", help="rule file or directory")
    s.add_argument("events", help="JSONL/JSON file, or - for stdin")
    s.add_argument("--min-level", choices=LEVELS, default="informational")
    s.add_argument("--format", choices=("text", "json"), default="text")
    s.add_argument("--fail-on-match", action="store_true", help="exit 1 if anything matches (CI use)")
    s.set_defaults(func=_cmd_scan)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (RuleError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
