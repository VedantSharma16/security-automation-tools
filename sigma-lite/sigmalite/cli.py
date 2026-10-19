"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from .engine import coverage, read_jsonl, scan_events
from .rule import LEVELS, RuleError, load_rules

DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules"


def _cmd_validate(args) -> int:
    try:
        rules = load_rules(args.rules)
    except RuleError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 2
    print(f"OK: {len(rules)} rules valid")
    return 0


def _cmd_scan(args) -> int:
    try:
        rules = load_rules(args.rules)
        with open(args.events, encoding="utf-8") as fh:
            matches = scan_events(rules, read_jsonl(fh), args.min_level)
    except (RuleError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps([
            {"rule_id": m.rule.id, "title": m.rule.title, "level": m.rule.level,
             "techniques": m.rule.techniques, "line": m.line, "event": m.event}
            for m in matches], indent=2))
    else:
        for m in sorted(matches, key=lambda m: (-LEVELS.index(m.rule.level), m.line)):
            tech = ",".join(m.rule.techniques) or "-"
            print(f"[{m.rule.level.upper():<8}] line {m.line:<4} {m.rule.title} ({tech})")
        counts = Counter(m.rule.level for m in matches)
        print(f"\n{len(matches)} alert(s): " + ", ".join(f"{counts[l]} {l}" for l in reversed(LEVELS) if counts[l]))
    return 1 if matches and args.fail_on_match else 0


def _cmd_coverage(args) -> int:
    try:
        rules = load_rules(args.rules)
    except RuleError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for tech, titles in coverage(rules).items():
        print(f"{tech:<10} {'; '.join(titles)}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sigmalite", description="Sigma-style detection engine")
    sub = p.add_subparsers(dest="cmd", required=True)
    rules_kw = dict(default=str(DEFAULT_RULES), help="rule file or directory (default: bundled rules)")

    v = sub.add_parser("validate", help="lint rules")
    v.add_argument("--rules", **rules_kw)
    v.set_defaults(fn=_cmd_validate)

    s = sub.add_parser("scan", help="evaluate rules against a JSONL event file")
    s.add_argument("events")
    s.add_argument("--rules", **rules_kw)
    s.add_argument("--min-level", choices=LEVELS, default="informational")
    s.add_argument("--format", choices=["text", "json"], default="text")
    s.add_argument("--fail-on-match", action="store_true", help="exit 1 if any alert fires (CI use)")
    s.set_defaults(fn=_cmd_scan)

    c = sub.add_parser("coverage", help="list ATT&CK techniques covered by the rules")
    c.add_argument("--rules", **rules_kw)
    c.set_defaults(fn=_cmd_coverage)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
