"""Command line interface: validate / run / coverage."""
from __future__ import annotations

import argparse
import json
import sys

from .coverage import coverage
from .engine import Engine, load_events
from .rule import LEVELS, RuleError, load_rules


def _cmd_validate(a) -> int:
    rules = load_rules(a.rules)
    print(f"OK: {len(rules)} rule(s) valid")
    return 0


def _cmd_run(a) -> int:
    rules = load_rules(a.rules)
    matches = list(Engine(rules, a.min_level).run(load_events(a.events)))
    if a.json:
        print(json.dumps([m.to_dict() for m in matches], indent=2))
    else:
        for m in matches:
            techs = ",".join(m.rule.techniques) or "-"
            print(f"[{m.rule.level.upper():<8}] {m.rule.title} (event #{m.index}, {techs})")
        print(f"\n{len(matches)} detection(s)")
    return 1 if matches and a.fail_on_match else 0


def _cmd_coverage(a) -> int:
    target = set(a.target.split(",")) if a.target else None
    rep = coverage(load_rules(a.rules), target)
    if a.json:
        print(json.dumps(rep, indent=2))
        return 0
    print(f"{rep['total_rules']} rules, {len(rep['techniques'])} techniques")
    for t, ids in rep["techniques"].items():
        print(f"  {t:<10} {', '.join(ids)}")
    if rep["rules_without_attack_mapping"]:
        print("Unmapped rules:", ", ".join(rep["rules_without_attack_mapping"]))
    if target is not None:
        print(f"Target coverage: {rep['target_coverage_pct']}%  gaps: {', '.join(rep['target_gaps']) or 'none'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sigma-lite", description="Sigma-compatible detection engine")
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="validate rule files")
    v.add_argument("rules")
    v.set_defaults(fn=_cmd_validate)
    r = sub.add_parser("run", help="run rules against JSON/JSONL events")
    r.add_argument("rules")
    r.add_argument("events")
    r.add_argument("--min-level", choices=LEVELS, default="informational")
    r.add_argument("--json", action="store_true")
    r.add_argument("--fail-on-match", action="store_true", help="exit 1 if anything matched (CI use)")
    r.set_defaults(fn=_cmd_run)
    c = sub.add_parser("coverage", help="ATT&CK coverage of a rule set")
    c.add_argument("rules")
    c.add_argument("--target", help="comma-separated technique IDs you want covered")
    c.add_argument("--json", action="store_true")
    c.set_defaults(fn=_cmd_coverage)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except (RuleError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
