"""Command-line interface.

    sigmalite scan     --rules rules/ --events samples/attack_chain.jsonl
    sigmalite test     --rules rules/
    sigmalite coverage --rules rules/
    sigmalite validate --rules rules/
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .attack import coverage
from .correlate import correlate
from .engine import Engine, load_field_map, read_events
from .report import to_json, to_markdown
from .rule import LEVEL_RANK, LEVELS, RuleError, load_rules
from .testing import run_rule_tests

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _add_rules_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument("--rules", required=True, help="rule file or directory of .yml rules")
    p.add_argument("--field-map", help="YAML mapping of Sigma field names to your log schema")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sigmalite", description="Lightweight Sigma detection engine.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="evaluate rules against an event log")
    _add_rules_arg(scan)
    scan.add_argument("--events", required=True, help="JSON Lines or JSON array of events")
    scan.add_argument("--format", choices=("markdown", "json"), default="markdown")
    scan.add_argument("--output", "-o", help="write the report to this file instead of stdout")
    scan.add_argument("--min-level", choices=LEVELS, default="informational")
    scan.add_argument("--window", type=float, default=30.0, help="incident correlation window in minutes")
    scan.add_argument("--fail-on", choices=LEVELS, default="high",
                      help="exit 1 if any incident is at or above this level (default: high)")

    for name, help_ in (("test", "run each rule's embedded match/no_match test cases"),
                        ("coverage", "report MITRE ATT&CK tactic/technique coverage"),
                        ("validate", "parse and compile every rule, reporting errors")):
        p = sub.add_parser(name, help=help_)
        _add_rules_arg(p)
        if name == "test":
            p.add_argument("--require-tests", action="store_true", help="fail if any rule has no test cases")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        field_map = load_field_map(args.field_map)
        rules = load_rules(args.rules, field_map)
    except (RuleError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.command == "validate":
        print(f"OK: {len(rules)} rule(s) compiled successfully")
        return EXIT_OK

    if args.command == "coverage":
        print(coverage(rules).to_markdown(), end="")
        return EXIT_OK

    if args.command == "test":
        report = run_rule_tests(rules)
        print(report.summary())
        if not report.ok or (args.require_tests and report.untested):
            return EXIT_FINDINGS
        return EXIT_OK

    # scan
    try:
        events = list(read_events(args.events))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    engine = Engine(rules, field_map, min_level=args.min_level)
    alerts = engine.scan(events)
    incidents = correlate(alerts, args.window)
    render = to_json if args.format == "json" else to_markdown
    text = render(alerts, incidents, len(events), len(engine.rules))
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"wrote {args.output}: {len(alerts)} alerts, {len(incidents)} incident(s)")
    else:
        print(text, end="")
    threshold = LEVEL_RANK[args.fail_on]
    return EXIT_FINDINGS if any(LEVEL_RANK[i.level] >= threshold for i in incidents) else EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
