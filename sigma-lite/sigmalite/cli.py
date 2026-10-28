"""Command line interface: ``sigmalite scan|validate|list``."""

from __future__ import annotations

import argparse
import json
import sys

from .engine import Engine, read_jsonl
from .rules import LEVELS, RuleError, load_rules


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sigmalite", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    scan = sub.add_parser("scan", help="run rules against a JSONL log file ('-' for stdin)")
    scan.add_argument("logs")
    scan.add_argument("-r", "--rules", required=True, help="rule file or directory")
    scan.add_argument("--min-level", choices=LEVELS, default="informational")
    scan.add_argument("--format", choices=["text", "json"], default="text")
    scan.add_argument("--fail-on", choices=LEVELS, help="exit 1 if any alert is at/above this level")
    val = sub.add_parser("validate", help="validate rule files")
    val.add_argument("rules")
    ls = sub.add_parser("list", help="list loaded rules with ATT&CK mapping")
    ls.add_argument("rules")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rules = load_rules(args.rules)
        if args.cmd == "validate":
            print(f"OK: {len(rules)} rule(s) valid")
            return 0
        if args.cmd == "list":
            for r in rules:
                print(f"{r.level:<13} {r.title}  [{', '.join(r.techniques) or '-'}]")
            return 0
        lines = sys.stdin if args.logs == "-" else open(args.logs, encoding="utf-8")
        with lines:
            engine = Engine(rules, args.min_level)
            alerts = engine.scan(read_jsonl(lines))
    except (RuleError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    summary = Engine.summarize(alerts)
    if args.format == "json":
        print(json.dumps({"summary": summary, "alerts": [a.to_dict() for a in alerts]}, indent=2))
    else:
        for a in alerts:
            print(f"[{a.level.upper()}] line {a.line}: {a.title} ({', '.join(a.techniques) or 'no ATT&CK'})")
        print(f"\n{summary['total']} alert(s); techniques: {', '.join(summary['techniques']) or 'none'}")
    if args.fail_on and any(LEVELS.index(a.level) >= LEVELS.index(args.fail_on) for a in alerts):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
