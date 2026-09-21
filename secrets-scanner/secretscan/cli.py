"""Command-line interface for secretscan."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import baseline as baseline_mod
from . import gitscan
from . import llm_triage
from . import report as report_mod
from . import scanner
from .rules import SEVERITIES, RuleValidationError, load_rules

# Exit codes let this tool slot into pre-commit hooks / CI pipelines that
# want to block a commit or fail a build when a secret is found.
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secretscan",
        description="Scan a directory and (optionally) its full git history for "
        "hardcoded secrets and credentials.",
    )
    parser.add_argument(
        "path", nargs="?", type=Path, default=Path("."),
        help="Directory to scan (default: current directory).",
    )
    parser.add_argument(
        "--rules", type=Path, default=None,
        help="Path to a YAML rule file (default: bundled rules).",
    )
    parser.add_argument(
        "--include-history", action="store_true",
        help="Also scan full git history (all branches/tags) for secrets that "
        "were committed and later removed.",
    )
    parser.add_argument(
        "--min-severity", choices=SEVERITIES, default="low",
        help="Only report findings at or above this severity (default: low).",
    )
    parser.add_argument(
        "--baseline", type=Path,
        help="Baseline file of allowlisted finding fingerprints, used to "
        "suppress known/accepted findings.",
    )
    parser.add_argument(
        "--create-baseline", action="store_true",
        help="Write the current findings to --baseline instead of reporting/"
        "failing on them.",
    )
    parser.add_argument(
        "--llm-triage", action="store_true",
        help="Use an LLM (ANTHROPIC_API_KEY) to triage ambiguous generic "
        "high-entropy findings; falls back to an offline heuristic if unset.",
    )
    parser.add_argument("--json-out", type=Path, help="Write the full JSON report to this path.")
    parser.add_argument(
        "--sarif-out", type=Path,
        help="Write a SARIF 2.1.0 report to this path, for GitHub code scanning / CI upload.",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output.")
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        rules = load_rules(args.rules)
        root = args.path.resolve()
        if not root.exists():
            raise FileNotFoundError(f"path not found: {root}")

        if args.create_baseline:
            if not args.baseline:
                print("error: --create-baseline requires --baseline PATH", file=sys.stderr)
                return EXIT_ERROR
            findings = scanner.scan(root, rules, include_history=args.include_history)
            baseline_mod.save_baseline(findings, args.baseline)
            print(f"Wrote baseline with {len(findings)} finding(s) to {args.baseline}")
            return EXIT_CLEAN

        baseline = baseline_mod.load_baseline(args.baseline) if args.baseline else set()
        findings = scanner.scan(
            root, rules, include_history=args.include_history, baseline=baseline
        )

        triager = llm_triage.get_triager(args.llm_triage)
        findings = triager.triage(findings)

        scanned_paths = [str(root)]
        if args.include_history:
            scanned_paths.append("git history (all refs)")

        report = report_mod.build_report(findings, scanned_paths)
        report = report_mod.filter_by_min_severity(report, args.min_severity)

        print(report_mod.render_console(report, use_color=not args.no_color))

        if args.json_out:
            report_mod.write_json(report, args.json_out)
        if args.sarif_out:
            report_mod.write_sarif(report, args.sarif_out)
    except (FileNotFoundError, gitscan.GitCommandError, RuleValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        return EXIT_CLEAN

    return EXIT_FINDINGS if report["finding_count"] else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
