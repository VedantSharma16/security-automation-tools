"""Command line interface: validate | run | coverage."""
from __future__ import annotations

import argparse
import json
import sys

from .engine import coverage, read_events, run, summarize
from .rules import RuleError, lint_rule, load_rules, _read
from pathlib import Path


def _cmd_validate(args) -> int:
    p = Path(args.rules)
    files = sorted(f for f in p.rglob("*") if f.suffix in (".json", ".yml", ".yaml")) if p.is_dir() else [p]
    bad = 0
    for f in files:
        try:
            problems = lint_rule(_read(f))
        except RuleError as exc:
            problems = [str(exc)]
        status = "OK  " if not problems else "FAIL"
        print(f"{status} {f}")
        for prob in problems:
            print(f"     - {prob}")
        bad += bool(problems)
    print(f"\n{len(files) - bad}/{len(files)} rules valid")
    return 1 if bad else 0


def _cmd_run(args) -> int:
    rules = load_rules(args.rules)
    detections = run(rules, read_events(args.events))
    summary = summarize(detections)
    if args.json:
        print(json.dumps({
            "summary": summary,
            "detections": [
                {"rule": d.rule.id, "title": d.rule.title, "level": d.rule.level,
                 "techniques": d.rule.techniques, "line": d.line, "event": d.event}
                for d in detections
            ],
        }, indent=2))
    else:
        for d in detections:
            ts = d.event.get("timestamp", "?")
            print(f"[{d.rule.level.upper():<8}] {d.rule.id} {d.rule.title}  "
                  f"(line {d.line}, {ts}, {','.join(d.rule.techniques) or '-'})")
        print(f"\n{summary['total']} detection(s); highest severity: {summary['highest_severity']}")
    return 2 if detections and args.fail_on_match else 0


def _cmd_coverage(args) -> int:
    rules = load_rules(args.rules)
    for tech, ids in coverage(rules).items():
        print(f"{tech:<10} {', '.join(ids)}")
    print(f"\n{len(coverage(rules))} technique(s) covered by {len(rules)} rule(s)")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="sigmalite", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="lint rule files")
    v.add_argument("rules")
    v.set_defaults(fn=_cmd_validate)
    r = sub.add_parser("run", help="replay a JSONL event file against rules")
    r.add_argument("rules")
    r.add_argument("events")
    r.add_argument("--json", action="store_true")
    r.add_argument("--fail-on-match", action="store_true", help="exit 2 if anything matched (CI gating)")
    r.set_defaults(fn=_cmd_run)
    c = sub.add_parser("coverage", help="ATT&CK technique coverage")
    c.add_argument("rules")
    c.set_defaults(fn=_cmd_coverage)
    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except (RuleError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
