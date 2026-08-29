"""Command-line entry point: run passive recon against a domain and emit a report."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import dns_recon, http_headers, subdomain_enum, tls_info
from .llm_summarizer import get_summarizer
from .report import build_report, to_json, to_markdown


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="asm",
        description=(
            "Passive external recon: DNS/email-security posture, certificate "
            "transparency subdomain discovery, HTTP security headers, and TLS "
            "certificate inspection. Only scan domains you're authorized to test."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan a domain and produce an attack-surface report.")
    scan.add_argument("domain", help="Domain to scan, e.g. example.com")
    scan.add_argument(
        "--format", choices=["json", "markdown"], default="markdown", help="Output format."
    )
    scan.add_argument("--out", help="Write the report to this file instead of stdout.")
    scan.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds.")
    scan.add_argument(
        "--no-subdomains", action="store_true", help="Skip certificate transparency subdomain enumeration."
    )
    scan.add_argument(
        "--llm",
        action="store_true",
        help="Use Claude to write the narrative section (requires ANTHROPIC_API_KEY).",
    )
    scan.add_argument("--model", default="claude-sonnet-5", help="Model to use when --llm is set.")

    return parser


def run_scan(args: argparse.Namespace) -> int:
    domain = args.domain
    findings = []

    records = dns_recon.resolve_records(domain, timeout=args.timeout)
    findings.extend(dns_recon.build_findings(domain, records))

    subdomains: list[str] = []
    if not args.no_subdomains:
        try:
            subdomains = subdomain_enum.query_crtsh(domain, timeout=args.timeout)
            findings.extend(subdomain_enum.build_findings(domain, subdomains))
        except subdomain_enum.SubdomainEnumError as exc:
            print(f"warning: subdomain enumeration failed: {exc}", file=sys.stderr)

    http_result = http_headers.analyze(domain, timeout=args.timeout)
    findings.extend(http_headers.build_findings(domain, http_result))

    tls_result = tls_info.get_certificate_info(domain, timeout=args.timeout)
    findings.extend(tls_info.build_findings(domain, tls_result))

    report = build_report(domain, records, subdomains, http_result, tls_result, findings)

    summarizer = get_summarizer(args.llm, model=args.model)
    report["narrative"] = summarizer.summarize(report)

    output = to_json(report) if args.format == "json" else to_markdown(report)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
    else:
        print(output)

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
