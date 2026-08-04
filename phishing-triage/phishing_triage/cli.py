"""Command-line entry point: parse an .eml file, run every analyzer, and emit a report."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .auth_analysis import analyze_authentication
from .content_analysis import analyze_attachments, analyze_content, analyze_sender
from .llm_summarizer import get_summarizer
from .parser import parse_email_bytes
from .report import build_report, render_console, to_json
from .scoring import Verdict, score_email
from .url_analysis import analyze_links


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishing-triage",
        description="Parse a raw .eml email and produce a scored phishing triage report.",
    )
    parser.add_argument(
        "file",
        nargs="?",
        help="Path to the .eml file to analyze. Reads raw email bytes from stdin if omitted.",
    )
    parser.add_argument("--json", action="store_true", help="Emit the report as JSON.")
    parser.add_argument("--out", help="Write the report to this file instead of stdout.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color in console output.")
    parser.add_argument(
        "--llm",
        action="store_true",
        help="Use Claude to write the narrative section (requires ANTHROPIC_API_KEY).",
    )
    parser.add_argument("--model", default="claude-sonnet-5", help="Model to use when --llm is set.")
    return parser


def run(args: argparse.Namespace) -> int:
    if args.file:
        path = Path(args.file)
        if not path.is_file():
            print(f"error: no such file: {path}", file=sys.stderr)
            return 2
        try:
            data = path.read_bytes()
        except OSError as exc:
            print(f"error: could not read {path}: {exc}", file=sys.stderr)
            return 2
    else:
        data = sys.stdin.buffer.read()

    try:
        parsed = parse_email_bytes(data)
    except Exception as exc:  # noqa: BLE001 - surface any parse failure as a clean CLI error
        print(f"error: could not parse email: {exc}", file=sys.stderr)
        return 2

    auth = analyze_authentication(parsed.authentication_results_raw)
    url_findings = analyze_links(parsed.links)
    content = analyze_content(parsed.subject, parsed.visible_text)
    sender = analyze_sender(parsed.from_display, parsed.from_domain)
    attachment_findings = analyze_attachments(parsed.attachments)
    triage = score_email(auth, url_findings, content, sender, attachment_findings)

    report = build_report(parsed, auth, url_findings, content, sender, attachment_findings, triage)

    summarizer = get_summarizer(args.llm, model=args.model)
    report["narrative"] = summarizer.summarize(report)

    output = to_json(report) if args.json else render_console(report, use_color=not args.no_color)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
    else:
        print(output)

    return 0 if triage.verdict == Verdict.BENIGN else 1


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
