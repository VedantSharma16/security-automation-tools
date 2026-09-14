"""Command-line entrypoint for the HTTP security auditor.

Usage:
    http-audit --url https://example.com
    http-audit --url https://example.com --check-exposed --json
    http-audit --url https://example.com --markdown

Only scan systems you are authorized to test.
"""

from __future__ import annotations

import argparse
import json
import sys

from http_audit.audit import run_audit
from http_audit.fetcher import FetchError
from http_audit.report import AuditReport

_SEVERITY_ICONS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
    "pass": "🟢",
}


def _render_human(report: AuditReport) -> str:
    lines = [
        f"Grade: {report.grade}  Score: {report.score}/100  HTTP status: {report.status_code}",
        f"LLM-backed: {'yes' if report.llm_backed else 'no (offline heuristic fallback)'}",
        "",
        f"Findings ({len(report.findings)}):",
    ]
    for f in report.sorted_findings():
        icon = _SEVERITY_ICONS.get(f.severity, "")
        lines.append(f"  {icon} [{f.severity.upper()}] ({f.category}) {f.name}: {f.message}")
        if f.recommendation:
            lines.append(f"      -> {f.recommendation}")
    lines.append("")
    lines.append("Summary:")
    lines.append(report.summary)
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="http-audit",
        description="Passive HTTP security posture audit: headers, cookies, CORS, and TLS checks, "
        "with a weighted score/grade and an LLM-backed remediation narrative. "
        "Only scan systems you are authorized to test.",
    )
    parser.add_argument("--url", "-u", required=True, help="Target URL, e.g. https://example.com")
    parser.add_argument("--json", action="store_true", help="Output the full report as JSON.")
    parser.add_argument("--markdown", action="store_true", help="Output the full report as Markdown.")
    parser.add_argument(
        "--check-exposed",
        action="store_true",
        help="Also probe for commonly-exposed sensitive paths (.git, .env, etc.) on the same host. "
        "Issues additional requests — only use against systems you are authorized to test.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        report = run_audit(args.url, check_exposed=args.check_exposed)
    except FetchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    elif args.markdown:
        print(report.to_markdown())
    else:
        print(_render_human(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
