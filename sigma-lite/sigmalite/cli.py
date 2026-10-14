"""Command line: sigmalite --rules RULES --events EVENTS.jsonl"""
from __future__ import annotations

import argparse
import json
import sys

from .engine import evaluate_events, read_jsonl, summarize
from .rules import LEVELS, RuleError, load_rules


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sigmalite", description=__doc__)
    ap.add_argument("--rules", required=True, help="rule file or directory")
    ap.add_argument("--events", required=True, help="JSONL events ('-' for stdin)")
    ap.add_argument("--min-level", choices=LEVELS, default="informational")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    args = ap.parse_args(argv)
    try:
        rules = load_rules(args.rules)
        fh = sys.stdin if args.events == "-" else open(args.events, encoding="utf-8")
        with fh:
            matches = evaluate_events(rules, read_jsonl(fh), args.min_level)
    except (RuleError, ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    summary = summarize(matches)
    if args.format == "json":
        print(json.dumps({"summary": summary, "alerts": [
            {"rule": m.rule.title, "id": m.rule.id, "level": m.rule.level,
             "techniques": m.rule.techniques, "line": m.line, "event": m.event}
            for m in matches]}, indent=2))
    else:
        for m in matches:
            tech = ",".join(m.rule.techniques) or "-"
            print(f"[{m.rule.level.upper():8}] line {m.line}: {m.rule.title} ({tech})")
        print(f"\n{len(rules)} rules, {summary['total']} alert(s)", end="")
        print(f" | techniques: {', '.join(summary['techniques'])}" if summary["techniques"] else "")
    return 1 if matches else 0


if __name__ == "__main__":
    sys.exit(main())
