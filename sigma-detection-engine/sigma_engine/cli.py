"""Command-line interface: ``sigma-engine {scan,lint,test,coverage}``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import read_events, scan
from .report import render_coverage_markdown, render_scan_markdown, render_test_text
from .rule import LEVELS, RuleError, lint_rules, load_rules
from .testing import TestSuiteError, run_rule_tests


def _write(text: str, out: str | None) -> None:
    if out:
        Path(out).write_text(text, encoding="utf-8")
        print(f"wrote {out}", file=sys.stderr)
    else:
        sys.stdout.write(text)


def cmd_scan(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules)
    result = scan(rules, read_events(args.events), min_level=args.min_level)
    if args.format == "json":
        _write(json.dumps(result.to_dict(), indent=2) + "\n", args.output)
    else:
        _write(render_scan_markdown(result), args.output)
    top = result.max_level()
    if args.fail_on and top and LEVELS.index(top) >= LEVELS.index(args.fail_on):
        return 1
    return 0


def cmd_lint(args: argparse.Namespace) -> int:
    issues = lint_rules(args.rules)
    for issue in issues:
        print(issue)
    errors = sum(1 for i in issues if i.severity == "error")
    warnings = len(issues) - errors
    print(f"\n{errors} error(s), {warnings} warning(s)")
    return 1 if errors or (args.strict and warnings) else 0


def cmd_test(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules)
    report = run_rule_tests(rules, args.tests)
    sys.stdout.write(render_test_text(report, len(rules)))
    if not report.ok:
        return 1
    if args.min_coverage is not None and report.coverage(len(rules)) * 100 < args.min_coverage:
        print(f"coverage below required {args.min_coverage}%")
        return 1
    return 0


def cmd_coverage(args: argparse.Namespace) -> int:
    _write(render_coverage_markdown(load_rules(args.rules)), args.output)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sigma-engine",
        description="Sigma-compatible detection engine with detection-as-code testing.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="run rules over a JSON/JSONL event file")
    s.add_argument("events", help="JSON-lines or JSON-array event file")
    s.add_argument("-r", "--rules", nargs="+", default=["rules"], help="rule files/directories")
    s.add_argument("-f", "--format", choices=["markdown", "json"], default="markdown")
    s.add_argument("-o", "--output", help="write report to file instead of stdout")
    s.add_argument("--min-level", choices=LEVELS, default="informational", help="skip lower-severity rules")
    s.add_argument("--fail-on", choices=LEVELS, help="exit 1 if any alert is at/above this level (CI gate)")
    s.set_defaults(func=cmd_scan)

    l = sub.add_parser("lint", help="validate rule syntax, metadata and ATT&CK tags")
    l.add_argument("rules", nargs="*", default=["rules"])
    l.add_argument("--strict", action="store_true", help="treat warnings as errors")
    l.set_defaults(func=cmd_lint)

    t = sub.add_parser("test", help="run detection unit tests (true/false positive cases)")
    t.add_argument("-r", "--rules", nargs="+", default=["rules"])
    t.add_argument("-t", "--tests", nargs="+", default=["rule-tests"])
    t.add_argument("--min-coverage", type=float, help="fail if fewer than N%% of rules have tests")
    t.set_defaults(func=cmd_test)

    c = sub.add_parser("coverage", help="render an ATT&CK coverage matrix for the rule set")
    c.add_argument("rules", nargs="*", default=["rules"])
    c.add_argument("-o", "--output")
    c.set_defaults(func=cmd_coverage)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (RuleError, TestSuiteError, FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
