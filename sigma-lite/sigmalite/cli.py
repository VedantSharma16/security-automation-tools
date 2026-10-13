"""Command line interface: ``sigmalite validate|scan``."""
from __future__ import annotations

import argparse
import json
import sys

from .engine import read_events, scan
from .rules import LEVELS, RuleError, load_rules


def _render_text(res, min_level: str) -> str:
    out = [f"Scanned {res.events_scanned} events ({res.skipped_lines} malformed lines skipped)"]
    shown = [a for a in res.alerts if LEVELS.index(a.level) >= LEVELS.index(min_level)]
    for a in sorted(shown, key=lambda a: (-LEVELS.index(a.level), a.line)):
        tech = ",".join(a.techniques) or "-"
        out.append(f"[{a.level.upper():<8}] line {a.line:<4} {a.title} ({tech})")
    out.append(f"{len(shown)} alert(s)")
    if res.by_technique():
        out.append("ATT&CK coverage: " + ", ".join(f"{t}x{n}" for t, n in sorted(res.by_technique().items())))
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sigmalite", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="validate rule files")
    v.add_argument("rules")
    s = sub.add_parser("scan", help="scan a JSONL event file")
    s.add_argument("rules")
    s.add_argument("events")
    s.add_argument("--min-level", choices=LEVELS, default="informational")
    s.add_argument("--format", choices=("text", "json"), default="text")
    s.add_argument("--fail-on", choices=LEVELS, help="exit 2 if an alert at/above this level fires")
    a = p.parse_args(argv)

    try:
        rules = load_rules(a.rules)
    except (RuleError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if a.cmd == "validate":
        print(f"{len(rules)} rule(s) valid")
        return 0

    try:
        res = scan(rules, read_events(a.events))
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if a.format == "json":
        print(json.dumps({
            "events_scanned": res.events_scanned,
            "skipped_lines": res.skipped_lines,
            "by_rule": dict(res.by_rule()),
            "by_technique": dict(res.by_technique()),
            "alerts": [vars(x) for x in res.alerts
                       if LEVELS.index(x.level) >= LEVELS.index(a.min_level)],
        }, indent=2))
    else:
        print(_render_text(res, a.min_level))
    if a.fail_on and res.max_level() and LEVELS.index(res.max_level()) >= LEVELS.index(a.fail_on):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
