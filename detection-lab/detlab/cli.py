"""Command-line interface: ``detlab {scan,lint,test,coverage,draft}``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .author import RuleAuthor, default_client
from .coverage import build_coverage, load_reference
from .engine import load_events, scan
from .rules import LEVELS, iter_rule_documents, lint_rule_data, load_rules
from .testing import load_test_cases, run_suite

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _print_load_errors(errors: dict[str, str]) -> None:
    for source, message in errors.items():
        print(f"[!] could not load {source}: {message}", file=sys.stderr)


def cmd_scan(args: argparse.Namespace) -> int:
    loaded = load_rules(args.rules)
    _print_load_errors(loaded.errors)
    events, event_errors = load_events(args.events)
    result = scan(loaded.rules, events, min_level=args.min_level)
    result.event_errors = event_errors

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(f"Scanned {result.events_scanned} events with {result.rules_loaded} rules "
              f"-> {len(result.alerts)} alert(s)")
        if event_errors:
            print(f"Skipped {len(event_errors)} malformed event line(s)")
        if result.alerts:
            print("\nBy level: " + ", ".join(f"{lvl}={n}" for lvl, n in result.by_level().items()))
            print("\nTimeline:")
            for alert in result.alerts:
                ts = alert.event.get("UtcTime") or alert.event.get("@timestamp") or f"event#{alert.event_index}"
                host = alert.event.get("Hostname") or alert.event.get("Computer") or "-"
                techs = ",".join(alert.techniques) or "-"
                print(f"  {ts}  {host:<10} [{alert.level.upper():<8}] {alert.rule_title}  ({techs})")
    if args.output:
        Path(args.output).write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    return EXIT_FINDINGS if result.alerts else EXIT_OK


def cmd_lint(args: argparse.Namespace) -> int:
    errors = warnings = 0
    for label, doc in iter_rule_documents(args.rules):
        issues = lint_rule_data(doc) if not isinstance(doc, Exception) else None
        if issues is None:
            print(f"{label}\n  ERROR: {doc}")
            errors += 1
            continue
        shown = [i for i in issues if args.strict or i.severity == "error" or not args.errors_only]
        if shown:
            print(label)
            for issue in shown:
                print(f"  {issue}")
        errors += sum(i.severity == "error" for i in issues)
        warnings += sum(i.severity == "warning" for i in issues)
    print(f"\n{errors} error(s), {warnings} warning(s)")
    failed = errors or (args.strict and warnings)
    return EXIT_FINDINGS if failed else EXIT_OK


def cmd_test(args: argparse.Namespace) -> int:
    loaded = load_rules(args.rules)
    _print_load_errors(loaded.errors)
    suite = run_suite(loaded.rules, load_test_cases(args.tests))
    for res in suite.results:
        status = "PASS" if res.passed else "FAIL"
        print(f"[{status}] {res.rule_title}  ({res.tp_total} TP / {res.tn_total} TN)")
        for msg in res.failure_messages():
            print(f"        - {msg}")
    for orphan in suite.orphan_tests:
        print(f"[FAIL] orphan test: {orphan}")
    for rule in suite.untested_rules:
        print(f"[----] untested: {rule.title}")
    passed = sum(r.passed for r in suite.results)
    print(f"\n{passed}/{len(suite.results)} rule tests passed; "
          f"{suite.coverage_pct:.0f}% of rules have tests")
    if loaded.errors:
        return EXIT_ERROR
    if not suite.passed or (args.require_all and suite.untested_rules):
        return EXIT_FINDINGS
    return EXIT_OK


def cmd_coverage(args: argparse.Namespace) -> int:
    loaded = load_rules(args.rules)
    _print_load_errors(loaded.errors)
    reference = load_reference(args.reference) if args.reference else None
    report = build_coverage(loaded.rules, reference)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return EXIT_OK
    print(f"ATT&CK coverage: {len(report.covered)} technique(s) across {len(report.by_tactic)} tactic(s); "
          f"{report.reference_coverage_pct:.0f}% of the reference set\n")
    for tactic, techs in report.by_tactic.items():
        print(f"{tactic}")
        for tech in techs:
            name = report.reference.get(tech, {}).get("name", "")
            print(f"  [x] {tech:<10} {name}")
            for title in report.covered[tech]:
                print(f"        <- {title}")
    if report.gaps:
        print("\nGaps (reference techniques with no rule):")
        for tactic, techs in report.gaps.items():
            names = ", ".join(f"{t} {report.reference[t]['name'].split(': ')[-1]}" for t in techs)
            print(f"  {tactic}: {names}")
    return EXIT_OK


def cmd_draft(args: argparse.Namespace) -> int:
    description = Path(args.description).read_text(encoding="utf-8") if Path(args.description).is_file() else args.description
    positives, p_err = load_events(args.positives)
    negatives, n_err = load_events(args.negatives) if args.negatives else ([], [])
    if p_err or n_err:
        print(f"[!] skipped malformed sample lines: {p_err + n_err}", file=sys.stderr)
    client = None if args.offline else default_client()
    mode = "LLM" if client else "offline synthesizer"
    print(f"Drafting rule with {mode} ({len(positives)} positive / {len(negatives)} negative samples)...", file=sys.stderr)

    author = RuleAuthor(client=client, max_iterations=args.max_iterations)
    tags = [t.strip() for t in args.tags.split(",")] if args.tags else None
    result = author.draft(description, positives, negatives, title=args.title, level=args.level, tags=tags)

    for n, attempt in enumerate(result.attempts, start=1):
        verdict = "accepted" if attempt.passed else f"rejected ({len(attempt.errors)} error(s))"
        print(f"  attempt {n} [{attempt.source}]: {verdict}", file=sys.stderr)
        for err in attempt.errors:
            print(f"      - {err}", file=sys.stderr)

    if args.out:
        Path(args.out).write_text(result.rule_yaml or "", encoding="utf-8")
        print(f"Wrote rule to {args.out}", file=sys.stderr)
    else:
        print(result.rule_yaml)
    return EXIT_OK if result.passed else EXIT_FINDINGS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="detlab",
        description="Sigma-compatible detection-as-code engine: scan, lint, test, measure ATT&CK coverage, and draft rules.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", help="run rules against JSON/JSONL events")
    p.add_argument("--rules", nargs="+", required=True, help="rule files or directories")
    p.add_argument("--events", required=True, help="JSON array or JSON Lines event file")
    p.add_argument("--min-level", choices=LEVELS, default="informational")
    p.add_argument("--json", action="store_true", help="print the full JSON result")
    p.add_argument("--output", help="also write the JSON result to this file")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("lint", help="validate rule syntax and metadata hygiene")
    p.add_argument("rules", nargs="+")
    p.add_argument("--strict", action="store_true", help="treat warnings as failures")
    p.add_argument("--errors-only", action="store_true", help="hide warnings in the output")
    p.set_defaults(func=cmd_lint)

    p = sub.add_parser("test", help="run true-positive / true-negative rule tests")
    p.add_argument("--rules", nargs="+", required=True)
    p.add_argument("--tests", nargs="+", required=True, help="test files or directories")
    p.add_argument("--require-all", action="store_true", help="fail if any rule has no tests")
    p.set_defaults(func=cmd_test)

    p = sub.add_parser("coverage", help="MITRE ATT&CK coverage and gap report")
    p.add_argument("--rules", nargs="+", required=True)
    p.add_argument("--reference", help="custom technique reference JSON")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_coverage)

    p = sub.add_parser("draft", help="draft a rule from labelled samples (LLM loop or offline synthesizer)")
    p.add_argument("--description", required=True, help="behaviour description, or a path to a text file")
    p.add_argument("--positives", required=True, help="events the rule must match (JSON/JSONL)")
    p.add_argument("--negatives", help="events the rule must not match (JSON/JSONL)")
    p.add_argument("--title")
    p.add_argument("--level", choices=LEVELS, default="medium")
    p.add_argument("--tags", help="comma-separated tags for synthesized rules, e.g. attack.defense_evasion,attack.t1070.001")
    p.add_argument("--max-iterations", type=int, default=3)
    p.add_argument("--offline", action="store_true", help="never call an LLM, even if ANTHROPIC_API_KEY is set")
    p.add_argument("--out", help="write the rule here instead of stdout")
    p.set_defaults(func=cmd_draft)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
